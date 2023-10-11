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

type SignatureFuncRef<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Signature>;

impl<TransportT: Transport> UnauthenticatedClient<TransportT> {
    fn new(transport: TransportT) -> Self {
        Self {
            next_message_id: MessageId(0),
            transport,
            pre_auth_hash: vec![0; 64],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn request<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        command: Command,
        credit_charge: Credits,
        credits_requested: Credits,
        session_id: Option<SessionId>,
        signature_func: Option<SignatureFuncRef<'_>>,
        tree_id: Option<TreeId>,
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
            message_id: self.next_message_id,
            process_id: ProcessId(0),
            tree_id: tree_id.unwrap_or(TreeId(0)),
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
            security_mode: SecurityMode::SIGNING_ENABLED,
            reserved: 0,
            capabilities: Capabilities::empty(),
            client_guid: Uuid::new(&mut rng),
            dialects: vec![Dialect::Smb3_1_1],
            negotiate_contexts: vec![NegotiateContext::Smb2PreauthIntegrityCapabilities(
                Smb2PreauthIntegrityCapabilities {
                    data_length: 38,
                    reserved: 0,
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
            None,
            request,
        )?;
        Ok(())
    }
}

struct AuthenticatedClient<TransportT> {
    unauth_client: UnauthenticatedClient<TransportT>,
    session_id: SessionId,
    signing_key: Vec<u8>,
}

impl<TransportT: Transport> AuthenticatedClient<TransportT> {
    fn new(transport: TransportT, username: &str, password: &str) -> Result<Self> {
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
            session_binding_request: false,
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Capabilities::empty(),
            channel: 0,
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

            request.security_blob = output_buffer.pop().unwrap().buffer;

            (resp_header, response) = unauth_client.request(
                Command::SessionSetup,
                Credits(0),
                Credits(130),
                Some(session_id),
                None,
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
        tree_id: Option<TreeId>,
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
            tree_id,
            request,
        )
    }

    fn tree_connect(&mut self, path: &str) -> Result<TreeId> {
        let (header, _): (_, TreeConnectResponse) = self.request(
            Command::TreeConnect,
            None,
            TreeConnectRequest {
                flags: TreeConnectFlags::empty(),
                path: path.into(),
            },
        )?;

        Ok(header.tree_id)
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

pub struct Client<TransportT> {
    auth_client: AuthenticatedClient<TransportT>,
    tree_id: TreeId,
}

impl<TransportT: Transport> Client<TransportT> {
    pub fn new(transport: TransportT, username: &str, password: &str, path: &str) -> Result<Self> {
        let mut auth_client = AuthenticatedClient::new(transport, username, password)?;
        let tree_id = auth_client.tree_connect(path)?;
        Ok(Self {
            auth_client,
            tree_id,
        })
    }

    pub fn open_root(&mut self) -> Result<FileId> {
        let (_, response): (_, CreateResponse) = self.auth_client.request(
            Command::Create,
            Some(self.tree_id),
            CreateRequest {
                security_flags: 0,
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                create_flags: 0,
                reserved: 0,
                desired_access: AccessMask::FILE_READ_DATA | AccessMask::FILE_READ_EA,
                file_attributes: FileAttributes::empty(),
                share_access: FileShareAccess::READ
                    | FileShareAccess::WRITE
                    | FileShareAccess::DELETE,
                create_disposition: FileCreateDisposition::OPEN,
                create_options: FileCreateOptions::empty(),
                name: "".into(),
                create_contexts: vec![],
            },
        )?;
        Ok(response.file_id)
    }

    pub fn query_directory(
        &mut self,
        file_id: FileId,
    ) -> Result<Vec<FileIdBothDirectoryInformation>> {
        let (_, response): (_, QueryDirectoryResponse<FileIdBothDirectoryInformation>) =
            self.auth_client.request(
                Command::QueryDirectory,
                Some(self.tree_id),
                QueryDirectoryRequest {
                    file_information_class: FileInformationClass::FileIdFullDirectoryInformation,
                    flags: QueryDirectoryFlags::empty(),
                    file_index: 0,
                    file_id,
                    output_buffer_length: 15380,
                    search_pattern: "*".into(),
                },
            )?;
        Ok(response.entries.into_iter().map(|e| e.body).collect())
    }
}
