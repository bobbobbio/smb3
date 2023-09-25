use sspi_bobbobbio as sspi;

use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use cmac::Mac as _;
use derive_more::From;
use rand::Rng as _;
use serde::Deserialize;
use sha2::Digest as _;
use smb3::*;
use sspi::builders::EmptyInitializeSecurityContext;
use sspi::{
    AuthIdentity, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm, SecurityBuffer,
    SecurityBufferType, SecurityStatus, Sspi, SspiImpl,
};
use std::{io, mem};

pub const PORT: u16 = 445;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    NtStatus(NtStatus),
    Sspi(sspi::Error),
    Seralization(serde_smb::Error),
    Io(io::Error),
}

pub trait Transport: io::Read + io::Write {}

impl<T> Transport for T where T: io::Read + io::Write {}

struct UnauthenticatedClient<TransportT> {
    next_message_id: MessageId,
    transport: TransportT,
    pre_auth_hash: Vec<u8>,
}

impl<TransportT: Transport> UnauthenticatedClient<TransportT> {
    fn new(transport: TransportT) -> Self {
        Self {
            next_message_id: MessageId(0),
            transport,
            pre_auth_hash: vec![0; 64],
        }
    }

    fn request<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        command: Command,
        credit_charge: Credits,
        credits_requested: Credits,
        session_id: Option<SessionId>,
        signature_func: Option<&mut dyn FnMut(&[u8]) -> Result<Signature>>,
        request: T,
    ) -> Result<(ResponseHeader, R)> {
        let header = RequestHeader {
            protocol_id: ProtocolId::new(),
            header_length: 64,
            credit_charge,
            channel_sequence: 0,
            command,
            credits_requested,
            flags: HeaderFlags::new().with_signing(signature_func.is_some()),
            chain_offset: 0,
            message_id: self.next_message_id.clone(),
            process_id: ProcessId(0),
            tree_id: TreeId(0),
            session_id: session_id.unwrap_or(SessionId(0)),
            signature: Signature([0; 16]),
        };
        self.next_message_id = MessageId(self.next_message_id.0 + 1);

        let mut req_bytes = serde_smb::to_vec(&(header, request))?;

        if let Some(func) = signature_func {
            let sig = func(&req_bytes[..])?;
            req_bytes[48..64].clone_from_slice(&sig.0[..]);
        } else {
            let mut hasher = sha2::Sha512::new();
            hasher.update(&self.pre_auth_hash);
            hasher.update(&req_bytes);
            self.pre_auth_hash = hasher.finalize().to_vec();
        }

        self.transport
            .write_u32::<BigEndian>(req_bytes.len() as u32)?;
        self.transport.write_all(&req_bytes)?;

        let len = self.transport.read_u32::<BigEndian>()?;
        let mut response_bytes = vec![0; len as usize];
        self.transport.read_exact(&mut response_bytes)?;

        let mut deser = serde_smb::Deserializer::new(&response_bytes[..]);
        let response_header: ResponseHeader = Deserialize::deserialize(&mut deser)?;

        if response_header.signature == Signature([0; 16]) {
            let mut hasher = sha2::Sha512::new();
            hasher.update(&self.pre_auth_hash);
            hasher.update(&response_bytes);
            self.pre_auth_hash = hasher.finalize().to_vec();
        }

        if response_header.nt_status == NtStatus::Success
            || response_header.nt_status == NtStatus::MoreProcessingRequired
        {
            let response_body: R = Deserialize::deserialize(&mut deser)?;
            Ok((response_header, response_body))
        } else {
            Err(Error::NtStatus(response_header.nt_status))
        }
    }

    fn negotiate(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();
        let pre_auth_salt = rng.gen::<[u8; 32]>().to_vec();
        let request = NegotiateRequest {
            size: 0x24,
            dialect_count: 1,
            security_mode: SecurityMode::SIGNING_ENABLED,
            reserved: 0,
            capabilities: Capabilities::empty(),
            client_guid: Uuid::new(&mut rng),
            negotiate_context_offset: 0x68,
            negotiate_context_count: 1,
            dialects: vec![Dialect::Smb3_1_1],
            negotiate_contexts: vec![NegotiateContext::Smb2PreauthIntegrityCapabilities(
                Smb2PreauthIntegrityCapabilities {
                    data_length: 38,
                    reserved: 0,
                    hash_algorithm_count: 1,
                    salt_length: 32,
                    hash_algorithms: vec![HashAlgorithm::Sha512],
                    salt: pre_auth_salt,
                },
            )],
        };

        let _response: (_, NegotiateResponse) = self.request(
            Command::Negotiate,
            Credits(0),
            Credits(10),
            None,
            None,
            request,
        )?;
        Ok(())
    }
}

pub struct Client<TransportT> {
    unauth_client: UnauthenticatedClient<TransportT>,
    session_id: SessionId,
    signing_key: Vec<u8>,
}

impl<TransportT: Transport> Client<TransportT> {
    pub fn new(transport: TransportT, username: &str, password: &str) -> Result<Self> {
        let mut unauth_client = UnauthenticatedClient::new(transport);

        unauth_client.negotiate()?;

        let mut ntlm = Ntlm::new();

        let identity = AuthIdentity {
            username: username.into(),
            password: String::from(password).into(),
            domain: None,
        };
        let mut acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute()?;

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut builder =
            EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
                .with_credentials_handle(&mut acq_cred_result.credentials_handle)
                .with_context_requirements(
                    ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                )
                .with_target_data_representation(DataRepresentation::Native)
                .with_target_name(&identity.username)
                .with_output(&mut output_buffer);

        let _result = ntlm.initialize_security_context_impl(&mut builder)?;

        let security_blob = output_buffer.pop().unwrap().buffer;
        let mut request = SessionSetupRequest {
            size: 0x19,
            session_binding_request: false,
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Capabilities::empty(),
            channel: 0,
            blob_offset: 0x58,
            blob_length: security_blob.len().try_into().unwrap(),
            previous_session_id: SessionId(0),
            security_blob,
        };

        let (mut resp_header, mut response): (ResponseHeader, SessionSetupResponse) = unauth_client
            .request(
                Command::SessionSetup,
                Credits(0),
                Credits(130),
                None,
                None,
                request.clone(),
            )?;

        let session_id = resp_header.session_id;

        while resp_header.nt_status == NtStatus::MoreProcessingRequired {
            let mut input_buffer = vec![SecurityBuffer::new(
                mem::take(&mut response.security_blob),
                SecurityBufferType::Token,
            )];

            let mut output_buffer =
                vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];
            let mut builder =
                EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
                    .with_credentials_handle(&mut acq_cred_result.credentials_handle)
                    .with_context_requirements(
                        ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                    )
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&identity.username)
                    .with_input(&mut input_buffer)
                    .with_output(&mut output_buffer);

            let result = ntlm.initialize_security_context_impl(&mut builder)?;

            if [
                SecurityStatus::CompleteAndContinue,
                SecurityStatus::CompleteNeeded,
            ]
            .contains(&result.status)
            {
                ntlm.complete_auth_token(&mut output_buffer)?;
            }

            let security_blob = output_buffer.pop().unwrap().buffer;
            request.blob_length = security_blob.len().try_into().unwrap();
            request.security_blob = security_blob;

            (resp_header, response) = unauth_client.request(
                Command::SessionSetup,
                Credits(0),
                Credits(130),
                Some(session_id),
                None,
                request.clone(),
            )?;
        }

        let session_key = ntlm.session_key().unwrap();
        assert_eq!(session_key.len(), 16);
        let signing_key = sp800_108_counter_kdf(
            16,
            &session_key,
            b"SMBSigningKey\0",
            &unauth_client.pre_auth_hash,
        );

        Ok(Self {
            unauth_client,
            session_id,
            signing_key,
        })
    }

    fn request<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        command: Command,
        request: T,
    ) -> Result<(ResponseHeader, R)> {
        let mut sig_func = |bytes: &[u8]| {
            let mut mac = cmac::Cmac::<aes::Aes128>::new_from_slice(&self.signing_key[..]).unwrap();
            mac.update(bytes);
            Ok(Signature(mac.finalize().into_bytes().into()))
        };
        self.unauth_client.request(
            command,
            Credits(1),
            Credits(64),
            Some(self.session_id),
            Some(&mut sig_func),
            request,
        )
    }

    pub fn tree_connect(&mut self, path: &str) -> Result<(TreeId, TreeConnectResponse)> {
        let path_bytes: Vec<u8> = path
            .encode_utf16()
            .map(|c| c.to_le_bytes().into_iter())
            .flatten()
            .collect();
        let (header, response): (_, TreeConnectResponse) = self.request(
            Command::TreeConnect,
            TreeConnectRequest {
                size: 0x9,
                flags: TreeConnectFlags::empty(),
                path_offset: 0x48,
                path_length: path_bytes.len().try_into().unwrap(),
                path: path_bytes,
            },
        )?;

        Ok((header.tree_id, response))
    }
}

fn sp800_108_counter_kdf(key_len: usize, secret: &[u8], label: &[u8], salt: &[u8]) -> Vec<u8> {
    let length: u32 = (key_len * 8).try_into().unwrap();

    let mut p = vec![];
    let mut counter: u32 = 1;

    while p.len() < key_len {
        let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
        hmac.update(&counter.to_be_bytes());
        hmac.update(label);
        hmac.update(&[0u8]);
        hmac.update(salt);
        hmac.update(&length.to_be_bytes());
        p.extend(hmac.finalize().into_bytes());
        counter += 1;
    }

    p.resize(key_len, 0);

    p
}
