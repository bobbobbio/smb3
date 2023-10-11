// for some reason the bitfield macro triggers this
#![allow(clippy::identity_op)]

use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use modular_bitfield::{bitfield, specifiers::*};
use serde::{Deserialize, Serialize};
use serde_dis::{DeserializeWithDiscriminant, SerializeWithDiscriminant};
use serde_smb::{align_to, size as smb_size, DeserializeSmbStruct, SerializeSmbStruct};
use std::fmt;

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    Ioctl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OplockBreak = 0x0012,
}

#[bitfield]
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct HeaderFlags {
    pub response: bool,
    pub r#async: bool,
    pub chained: bool,
    pub signing: bool,
    pub priority: B3,
    pub unused1: B21,
    pub dfs: bool,
    pub replay: bool,
    pub unused2: B2,
}

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, PartialEq)]
pub struct MessageId(pub u64);

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, PartialEq)]
pub struct ProcessId(pub u32);

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, PartialEq)]
pub struct TreeId(pub u32);

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, PartialEq)]
pub struct SessionId(pub u64);

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Signature(pub [u8; 16]);

#[derive(Serialize, Deserialize, Default, Copy, Clone, Debug, PartialEq)]
pub struct Credits(pub u16);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
pub struct RequestHeader {
    pub protocol_id: ProtocolId,
    pub header_length: u16,
    pub credit_charge: Credits,
    pub channel_sequence: u16,
    #[smb(pad = 4)]
    pub command: Command,
    pub credits_requested: Credits,
    pub flags: HeaderFlags,
    pub chain_offset: u32,
    pub message_id: MessageId,
    pub process_id: ProcessId,
    pub tree_id: TreeId,
    pub session_id: SessionId,
    pub signature: Signature,
}

const HEADER_SIZE: usize = 64;

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum NtStatus {
    Success = 0x00000000,
    InvalidSmb = 0x00010002,
    BadTid = 0x00050002,
    BadCommand = 0x00160002,
    BadUid = 0x005b0002,
    UseStandard = 0x00fb0002,
    BufferOverflow = 0x80000005,
    NoMoreFiles = 0x80000006,
    StoppedOnSymlink = 0x8000002d,
    Unsuccessful = 0xc0000001,
    NotImplemented = 0xc0000002,
    InvalidInfoClass = 0xc0000003,
    InfoLengthMismatch = 0xc0000004,
    AccessViolation = 0xc0000005,
    InPageError = 0xc0000006,
    PagefileQuota = 0xc0000007,
    InvalidHandle = 0xc0000008,
    BadInitialStack = 0xc0000009,
    BadInitialPc = 0xc000000a,
    InvalidCid = 0xc000000b,
    TimerNotCanceled = 0xc000000c,
    InvalidParameter = 0xc000000d,
    NoSuchDevice = 0xc000000e,
    NoSuchFile = 0xc000000f,
    InvalidDeviceRequest = 0xc0000010,
    EndOfFile = 0xc0000011,
    WrongVolume = 0xc0000012,
    NoMediaInDevice = 0xc0000013,
    UnrecognizedMedia = 0xc0000014,
    NonexistentSector = 0xc0000015,
    MoreProcessingRequired = 0xc0000016,
    NoMemory = 0xc0000017,
    ConflictingAddresses = 0xc0000018,
    NotMappedView = 0xc0000019,
    UnableToFreeVm = 0xc000001a,
    UnableToDeleteSection = 0xc000001b,
    InvalidSystemService = 0xc000001c,
    IllegalInstruction = 0xc000001d,
    InvalidLockSequence = 0xc000001e,
    InvalidViewSize = 0xc000001f,
    InvalidFileForSection = 0xc0000020,
    AlreadyCommitted = 0xc0000021,
    AccessDenied = 0xc0000022,
    BufferTooSmall = 0xc0000023,
    ObjectTypeMismatch = 0xc0000024,
    NoncontinuableException = 0xc0000025,
    InvalidDisposition = 0xc0000026,
    Unwind = 0xc0000027,
    BadStack = 0xc0000028,
    InvalidUnwindTarget = 0xc0000029,
    NotLocked = 0xc000002a,
    ParityError = 0xc000002b,
    UnableToDecommitVm = 0xc000002c,
    NotCommitted = 0xc000002d,
    InvalidPortAttributes = 0xc000002e,
    PortMessageTooLong = 0xc000002f,
    InvalidParameterMix = 0xc0000030,
    InvalidQuotaLower = 0xc0000031,
    DiskCorruptError = 0xc0000032,
    ObjectNameInvalid = 0xc0000033,
    ObjectNameNotFound = 0xc0000034,
    ObjectNameCollision = 0xc0000035,
    HandleNotWaitable = 0xc0000036,
    PortDisconnected = 0xc0000037,
    DeviceAlreadyAttached = 0xc0000038,
    ObjectPathInvalid = 0xc0000039,
    ObjectPathNotFound = 0xc000003a,
    ObjectPathSyntaxBad = 0xc000003b,
    DataOverrun = 0xc000003c,
    DataLateError = 0xc000003d,
    DataError = 0xc000003e,
    CrcError = 0xc000003f,
    SectionTooBig = 0xc0000040,
    PortConnectionRefused = 0xc0000041,
    InvalidPortHandle = 0xc0000042,
    SharingViolation = 0xc0000043,
    QuotaExceeded = 0xc0000044,
    InvalidPageProtection = 0xc0000045,
    MutantNotOwned = 0xc0000046,
    SemaphoreLimitExceeded = 0xc0000047,
    PortAlreadySet = 0xc0000048,
    SectionNotImage = 0xc0000049,
    SuspendCountExceeded = 0xc000004a,
    ThreadIsTerminating = 0xc000004b,
    BadWorkingSetLimit = 0xc000004c,
    IncompatibleFileMap = 0xc000004d,
    SectionProtection = 0xc000004e,
    EasNotSupported = 0xc000004f,
    EaTooLarge = 0xc0000050,
    NonexistentEaEntry = 0xc0000051,
    NoEasOnFile = 0xc0000052,
    EaCorruptError = 0xc0000053,
    FileLockConflict = 0xc0000054,
    LockNotGranted = 0xc0000055,
    DeletePending = 0xc0000056,
    CtlFileNotSupported = 0xc0000057,
    UnknownRevision = 0xc0000058,
    RevisionMismatch = 0xc0000059,
    InvalidOwner = 0xc000005a,
    InvalidPrimaryGroup = 0xc000005b,
    NoImpersonationToken = 0xc000005c,
    CantDisableMandatory = 0xc000005d,
    NoLogonServers = 0xc000005e,
    NoSuchLogonSession = 0xc000005f,
    NoSuchPrivilege = 0xc0000060,
    PrivilegeNotHeld = 0xc0000061,
    InvalidAccountName = 0xc0000062,
    UserExists = 0xc0000063,
    NoSuchUser = 0xc0000064,
    GroupExists = 0xc0000065,
    NoSuchGroup = 0xc0000066,
    MemberInGroup = 0xc0000067,
    MemberNotInGroup = 0xc0000068,
    LastAdmin = 0xc0000069,
    WrongPassword = 0xc000006a,
    IllFormedPassword = 0xc000006b,
    PasswordRestriction = 0xc000006c,
    LogonFailure = 0xc000006d,
    AccountRestriction = 0xc000006e,
    InvalidLogonHours = 0xc000006f,
    InvalidWorkstation = 0xc0000070,
    PasswordExpired = 0xc0000071,
    AccountDisabled = 0xc0000072,
    NoneMapped = 0xc0000073,
    TooManyLuidsRequested = 0xc0000074,
    LuidsExhausted = 0xc0000075,
    InvalidSubAuthority = 0xc0000076,
    InvalidAcl = 0xc0000077,
    InvalidSid = 0xc0000078,
    InvalidSecurityDescr = 0xc0000079,
    ProcedureNotFound = 0xc000007a,
    InvalidImageFormat = 0xc000007b,
    NoToken = 0xc000007c,
    BadInheritanceAcl = 0xc000007d,
    RangeNotLocked = 0xc000007e,
    DiskFull = 0xc000007f,
    ServerDisabled = 0xc0000080,
    ServerNotDisabled = 0xc0000081,
    TooManyGuidsRequested = 0xc0000082,
    GuidsExhausted = 0xc0000083,
    InvalidIdAuthority = 0xc0000084,
    AgentsExhausted = 0xc0000085,
    InvalidVolumeLabel = 0xc0000086,
    SectionNotExtended = 0xc0000087,
    NotMappedData = 0xc0000088,
    ResourceDataNotFound = 0xc0000089,
    ResourceTypeNotFound = 0xc000008a,
    ResourceNameNotFound = 0xc000008b,
    ArrayBoundsExceeded = 0xc000008c,
    FloatDenormalOperand = 0xc000008d,
    FloatDivideByZero = 0xc000008e,
    FloatInexactResult = 0xc000008f,
    FloatInvalidOperation = 0xc0000090,
    FloatOverflow = 0xc0000091,
    FloatStackCheck = 0xc0000092,
    FloatUnderflow = 0xc0000093,
    IntegerDivideByZero = 0xc0000094,
    IntegerOverflow = 0xc0000095,
    PrivilegedInstruction = 0xc0000096,
    TooManyPagingFiles = 0xc0000097,
    FileInvalid = 0xc0000098,
    AllottedSpaceExceeded = 0xc0000099,
    InsufficientResources = 0xc000009a,
    DfsExitPathFound = 0xc000009b,
    DeviceDataError = 0xc000009c,
    DeviceNotConnected = 0xc000009d,
    DevicePowerFailure = 0xc000009e,
    FreeVmNotAtBase = 0xc000009f,
    MemoryNotAllocated = 0xc00000a0,
    WorkingSetQuota = 0xc00000a1,
    MediaWriteProtected = 0xc00000a2,
    DeviceNotReady = 0xc00000a3,
    InvalidGroupAttributes = 0xc00000a4,
    BadImpersonationLevel = 0xc00000a5,
    CantOpenAnonymous = 0xc00000a6,
    BadValidationClass = 0xc00000a7,
    BadTokenType = 0xc00000a8,
    BadMasterBootRecord = 0xc00000a9,
    InstructionMisalignment = 0xc00000aa,
    InstanceNotAvailable = 0xc00000ab,
    PipeNotAvailable = 0xc00000ac,
    InvalidPipeState = 0xc00000ad,
    PipeBusy = 0xc00000ae,
    IllegalFunction = 0xc00000af,
    PipeDisconnected = 0xc00000b0,
    PipeClosing = 0xc00000b1,
    PipeConnected = 0xc00000b2,
    PipeListening = 0xc00000b3,
    InvalidReadMode = 0xc00000b4,
    IoTimeout = 0xc00000b5,
    FileForcedClosed = 0xc00000b6,
    ProfilingNotStarted = 0xc00000b7,
    ProfilingNotStopped = 0xc00000b8,
    CouldNotInterpret = 0xc00000b9,
    FileIsADirectory = 0xc00000ba,
    NotSupported = 0xc00000bb,
    RemoteNotListening = 0xc00000bc,
    DuplicateName = 0xc00000bd,
    BadNetworkPath = 0xc00000be,
    NetworkBusy = 0xc00000bf,
    DeviceDoesNotExist = 0xc00000c0,
    TooManyCommands = 0xc00000c1,
    AdapterHardwareError = 0xc00000c2,
    InvalidNetworkResponse = 0xc00000c3,
    UnexpectedNetworkError = 0xc00000c4,
    BadRemoteAdapter = 0xc00000c5,
    PrintQueueFull = 0xc00000c6,
    NoSpoolSpace = 0xc00000c7,
    PrintCancelled = 0xc00000c8,
    NetworkNameDeleted = 0xc00000c9,
    NetworkAccessDenied = 0xc00000ca,
    BadDeviceType = 0xc00000cb,
    BadNetworkName = 0xc00000cc,
    TooManyNames = 0xc00000cd,
    TooManySessions = 0xc00000ce,
    SharingPaused = 0xc00000cf,
    RequestNotAccepted = 0xc00000d0,
    RedirectorPaused = 0xc00000d1,
    NetWriteFault = 0xc00000d2,
    ProfilingAtLimit = 0xc00000d3,
    NotSameDevice = 0xc00000d4,
    FileRenamed = 0xc00000d5,
    VirtualCircuitClosed = 0xc00000d6,
    NoSecurityOnObject = 0xc00000d7,
    CantWait = 0xc00000d8,
    PipeEmpty = 0xc00000d9,
    CantAccessDomainInfo = 0xc00000da,
    CantTerminateSelf = 0xc00000db,
    InvalidServerState = 0xc00000dc,
    InvalidDomainState = 0xc00000dd,
    InvalidDomainRole = 0xc00000de,
    NoSuchDomain = 0xc00000df,
    DomainExists = 0xc00000e0,
    DomainLimitExceeded = 0xc00000e1,
    OplockNotGranted = 0xc00000e2,
    InvalidOplockProtocol = 0xc00000e3,
    InternalDbCorruption = 0xc00000e4,
    InternalError = 0xc00000e5,
    GenericNotMapped = 0xc00000e6,
    BadDescriptorFormat = 0xc00000e7,
    InvalidUserBuffer = 0xc00000e8,
    UnexpectedIoError = 0xc00000e9,
    UnexpectedMmCreateErr = 0xc00000ea,
    UnexpectedMmMapError = 0xc00000eb,
    UnexpectedMmExtendErr = 0xc00000ec,
    NotLogonProcess = 0xc00000ed,
    LogonSessionExists = 0xc00000ee,
    InvalidParameter1 = 0xc00000ef,
    InvalidParameter2 = 0xc00000f0,
    InvalidParameter3 = 0xc00000f1,
    InvalidParameter4 = 0xc00000f2,
    InvalidParameter5 = 0xc00000f3,
    InvalidParameter6 = 0xc00000f4,
    InvalidParameter7 = 0xc00000f5,
    InvalidParameter8 = 0xc00000f6,
    InvalidParameter9 = 0xc00000f7,
    InvalidParameter10 = 0xc00000f8,
    InvalidParameter11 = 0xc00000f9,
    InvalidParameter12 = 0xc00000fa,
    RedirectorNotStarted = 0xc00000fb,
    RedirectorStarted = 0xc00000fc,
    StackOverflow = 0xc00000fd,
    NoSuchPackage = 0xc00000fe,
    BadFunctionTable = 0xc00000ff,
    DirectoryNotEmpty = 0xc0000101,
    FileCorruptError = 0xc0000102,
    NotADirectory = 0xc0000103,
    BadLogonSessionState = 0xc0000104,
    LogonSessionCollision = 0xc0000105,
    NameTooLong = 0xc0000106,
    FilesOpen = 0xc0000107,
    ConnectionInUse = 0xc0000108,
    MessageNotFound = 0xc0000109,
    ProcessIsTerminating = 0xc000010a,
    InvalidLogonType = 0xc000010b,
    NoGuidTranslation = 0xc000010c,
    CannotImpersonate = 0xc000010d,
    ImageAlreadyLoaded = 0xc000010e,
    AbiosNotPresent = 0xc000010f,
    AbiosLidNotExist = 0xc0000110,
    AbiosLidAlreadyOwned = 0xc0000111,
    AbiosNotLidOwner = 0xc0000112,
    AbiosInvalidCommand = 0xc0000113,
    AbiosInvalidLid = 0xc0000114,
    AbiosSelectorNotAvailable = 0xc0000115,
    AbiosInvalidSelector = 0xc0000116,
    NoLdt = 0xc0000117,
    InvalidLdtSize = 0xc0000118,
    InvalidLdtOffset = 0xc0000119,
    InvalidLdtDescriptor = 0xc000011a,
    InvalidImageNeFormat = 0xc000011b,
    RxactInvalidState = 0xc000011c,
    RxactCommitFailure = 0xc000011d,
    MappedFileSizeZero = 0xc000011e,
    TooManyOpenedFiles = 0xc000011f,
    Cancelled = 0xc0000120,
    CannotDelete = 0xc0000121,
    InvalidComputerName = 0xc0000122,
    FileDeleted = 0xc0000123,
    SpecialAccount = 0xc0000124,
    SpecialGroup = 0xc0000125,
    SpecialUser = 0xc0000126,
    MembersPrimaryGroup = 0xc0000127,
    FileClosed = 0xc0000128,
    TooManyThreads = 0xc0000129,
    ThreadNotInProcess = 0xc000012a,
    TokenAlreadyInUse = 0xc000012b,
    PagefileQuotaExceeded = 0xc000012c,
    CommitmentLimit = 0xc000012d,
    InvalidImageLeFormat = 0xc000012e,
    InvalidImageNotMz = 0xc000012f,
    InvalidImageProtect = 0xc0000130,
    InvalidImageWin16 = 0xc0000131,
    LogonServerConflict = 0xc0000132,
    TimeDifferenceAtDc = 0xc0000133,
    SynchronizationRequired = 0xc0000134,
    DllNotFound = 0xc0000135,
    OpenFailed = 0xc0000136,
    IoPrivilegeFailed = 0xc0000137,
    OrdinalNotFound = 0xc0000138,
    EntrypointNotFound = 0xc0000139,
    ControlCExit = 0xc000013a,
    LocalDisconnect = 0xc000013b,
    RemoteDisconnect = 0xc000013c,
    RemoteResources = 0xc000013d,
    LinkFailed = 0xc000013e,
    LinkTimeout = 0xc000013f,
    InvalidConnection = 0xc0000140,
    InvalidAddress = 0xc0000141,
    DllInitFailed = 0xc0000142,
    MissingSystemfile = 0xc0000143,
    UnhandledException = 0xc0000144,
    AppInitFailure = 0xc0000145,
    PagefileCreateFailed = 0xc0000146,
    NoPagefile = 0xc0000147,
    InvalidLevel = 0xc0000148,
    WrongPasswordCore = 0xc0000149,
    IllegalFloatContext = 0xc000014a,
    PipeBroken = 0xc000014b,
    RegistryCorrupt = 0xc000014c,
    RegistryIoFailed = 0xc000014d,
    NoEventPair = 0xc000014e,
    UnrecognizedVolume = 0xc000014f,
    SerialNoDeviceInited = 0xc0000150,
    NoSuchAlias = 0xc0000151,
    MemberNotInAlias = 0xc0000152,
    MemberInAlias = 0xc0000153,
    AliasExists = 0xc0000154,
    LogonNotGranted = 0xc0000155,
    TooManySecrets = 0xc0000156,
    SecretTooLong = 0xc0000157,
    InternalDbError = 0xc0000158,
    FullscreenMode = 0xc0000159,
    TooManyContextIds = 0xc000015a,
    LogonTypeNotGranted = 0xc000015b,
    NotRegistryFile = 0xc000015c,
    NtCrossEncryptionRequired = 0xc000015d,
    DomainCtrlrConfigError = 0xc000015e,
    FtMissingMember = 0xc000015f,
    IllFormedServiceEntry = 0xc0000160,
    IllegalCharacter = 0xc0000161,
    UnmappableCharacter = 0xc0000162,
    UndefinedCharacter = 0xc0000163,
    FloppyVolume = 0xc0000164,
    FloppyIdMarkNotFound = 0xc0000165,
    FloppyWrongCylinder = 0xc0000166,
    FloppyUnknownError = 0xc0000167,
    FloppyBadRegisters = 0xc0000168,
    DiskRecalibrateFailed = 0xc0000169,
    DiskOperationFailed = 0xc000016a,
    DiskResetFailed = 0xc000016b,
    SharedIrqBusy = 0xc000016c,
    FtOrphaning = 0xc000016d,
    PartitionFailure = 0xc0000172,
    InvalidBlockLength = 0xc0000173,
    DeviceNotPartitioned = 0xc0000174,
    UnableToLockMedia = 0xc0000175,
    UnableToUnloadMedia = 0xc0000176,
    EomOverflow = 0xc0000177,
    NoMedia = 0xc0000178,
    NoSuchMember = 0xc000017a,
    InvalidMember = 0xc000017b,
    KeyDeleted = 0xc000017c,
    NoLogSpace = 0xc000017d,
    TooManySids = 0xc000017e,
    LmCrossEncryptionRequired = 0xc000017f,
    KeyHasChildren = 0xc0000180,
    ChildMustBeVolatile = 0xc0000181,
    DeviceConfigurationError = 0xc0000182,
    DriverInternalError = 0xc0000183,
    InvalidDeviceState = 0xc0000184,
    IoDeviceError = 0xc0000185,
    DeviceProtocolError = 0xc0000186,
    BackupController = 0xc0000187,
    LogFileFull = 0xc0000188,
    TooLate = 0xc0000189,
    NoTrustLsaSecret = 0xc000018a,
    NoTrustSamAccount = 0xc000018b,
    TrustedDomainFailure = 0xc000018c,
    TrustedRelationshipFailure = 0xc000018d,
    EventlogFileCorrupt = 0xc000018e,
    EventlogCantStart = 0xc000018f,
    TrustFailure = 0xc0000190,
    MutantLimitExceeded = 0xc0000191,
    NetlogonNotStarted = 0xc0000192,
    AccountExpired = 0xc0000193,
    PossibleDeadlock = 0xc0000194,
    NetworkCredentialConflict = 0xc0000195,
    RemoteSessionLimit = 0xc0000196,
    EventlogFileChanged = 0xc0000197,
    NologonInterdomainTrustAccount = 0xc0000198,
    NologonWorkstationTrustAccount = 0xc0000199,
    NologonServerTrustAccount = 0xc000019a,
    DomainTrustInconsistent = 0xc000019b,
    FsDriverRequired = 0xc000019c,
    NoUserSessionKey = 0xc0000202,
    UserSessionDeleted = 0xc0000203,
    ResourceLangNotFound = 0xc0000204,
    InsuffServerResources = 0xc0000205,
    InvalidBufferSize = 0xc0000206,
    InvalidAddressComponent = 0xc0000207,
    InvalidAddressWildcard = 0xc0000208,
    TooManyAddresses = 0xc0000209,
    AddressAlreadyExists = 0xc000020a,
    AddressClosed = 0xc000020b,
    ConnectionDisconnected = 0xc000020c,
    ConnectionReset = 0xc000020d,
    TooManyNodes = 0xc000020e,
    TransactionAborted = 0xc000020f,
    TransactionTimedOut = 0xc0000210,
    TransactionNoRelease = 0xc0000211,
    TransactionNoMatch = 0xc0000212,
    TransactionResponded = 0xc0000213,
    TransactionInvalidId = 0xc0000214,
    TransactionInvalidType = 0xc0000215,
    NotServerSession = 0xc0000216,
    NotClientSession = 0xc0000217,
    CannotLoadRegistryFile = 0xc0000218,
    DebugAttachFailed = 0xc0000219,
    SystemProcessTerminated = 0xc000021a,
    DataNotAccepted = 0xc000021b,
    NoBrowserServersFound = 0xc000021c,
    VdmHardError = 0xc000021d,
    DriverCancelTimeout = 0xc000021e,
    ReplyMessageMismatch = 0xc000021f,
    MappedAlignment = 0xc0000220,
    ImageChecksumMismatch = 0xc0000221,
    LostWritebehindData = 0xc0000222,
    ClientServerParametersInvalid = 0xc0000223,
    PasswordMustChange = 0xc0000224,
    NotFound = 0xc0000225,
    NotTinyStream = 0xc0000226,
    RecoveryFailure = 0xc0000227,
    StackOverflowRead = 0xc0000228,
    FailCheck = 0xc0000229,
    DuplicateObjectid = 0xc000022a,
    ObjectidExists = 0xc000022b,
    ConvertToLarge = 0xc000022c,
    Retry = 0xc000022d,
    FoundOutOfScope = 0xc000022e,
    AllocateBucket = 0xc000022f,
    PropsetNotFound = 0xc0000230,
    MarshallOverflow = 0xc0000231,
    InvalidVariant = 0xc0000232,
    DomainControllerNotFound = 0xc0000233,
    AccountLockedOut = 0xc0000234,
    HandleNotClosable = 0xc0000235,
    ConnectionRefused = 0xc0000236,
    GracefulDisconnect = 0xc0000237,
    AddressAlreadyAssociated = 0xc0000238,
    AddressNotAssociated = 0xc0000239,
    ConnectionInvalid = 0xc000023a,
    ConnectionActive = 0xc000023b,
    NetworkUnreachable = 0xc000023c,
    HostUnreachable = 0xc000023d,
    ProtocolUnreachable = 0xc000023e,
    PortUnreachable = 0xc000023f,
    RequestAborted = 0xc0000240,
    ConnectionAborted = 0xc0000241,
    BadCompressionBuffer = 0xc0000242,
    UserMappedFile = 0xc0000243,
    AuditFailed = 0xc0000244,
    TimerResolutionNotSet = 0xc0000245,
    ConnectionCountLimit = 0xc0000246,
    LoginTimeRestriction = 0xc0000247,
    LoginWkstaRestriction = 0xc0000248,
    ImageMpUpMismatch = 0xc0000249,
    InsufficientLogonInfo = 0xc0000250,
    BadDllEntrypoint = 0xc0000251,
    BadServiceEntrypoint = 0xc0000252,
    LpcReplyLost = 0xc0000253,
    IpAddressConflict1 = 0xc0000254,
    IpAddressConflict2 = 0xc0000255,
    RegistryQuotaLimit = 0xc0000256,
    PathNotCovered = 0xc0000257,
    NoCallbackActive = 0xc0000258,
    LicenseQuotaExceeded = 0xc0000259,
    PwdTooShort = 0xc000025a,
    PwdTooRecent = 0xc000025b,
    PwdHistoryConflict = 0xc000025c,
    PlugplayNoDevice = 0xc000025e,
    UnsupportedCompression = 0xc000025f,
    InvalidHwProfile = 0xc0000260,
    InvalidPlugplayDevicePath = 0xc0000261,
    DriverOrdinalNotFound = 0xc0000262,
    DriverEntrypointNotFound = 0xc0000263,
    ResourceNotOwned = 0xc0000264,
    TooManyLinks = 0xc0000265,
    QuotaListInconsistent = 0xc0000266,
    FileIsOffline = 0xc0000267,
    Networksessionexpired = 0xc000035c,
    Toomanyuids = 0xc000205a,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ProtocolId([u8; 4]);

impl Default for ProtocolId {
    fn default() -> Self {
        Self(*b"\xfeSMB")
    }
}

impl ProtocolId {
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProtocolId")
            .field(&String::from_utf8_lossy(&self.0[..]))
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ResponseHeader {
    pub protocol_id: ProtocolId,
    pub header_length: u16,
    pub credit_charge: Credits,
    pub nt_status: NtStatus,
    pub command: Command,
    pub credits_granted: Credits,
    pub flags: HeaderFlags,
    pub chain_offset: u32,
    pub message_id: MessageId,
    pub process_id: ProcessId,
    pub tree_id: TreeId,
    pub session_id: SessionId,
    pub signature: Signature,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct SecurityMode: u8 {
        const SIGNING_ENABLED = 0x00000001;
        const SIGNING_REQURED = 0x00000002;
    }
}

impl_serde_for_bitflags!(SecurityMode);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct Capabilities: u32 {
        const DFS                = 0b00000001;
        const LEASING            = 0b00000010;
        const LARGE_MTU          = 0b00000100;
        const MULTI_CHANNEL      = 0b00001000;
        const PERSISTENT_HANDLES = 0b00010000;
        const DIRECTORY_LEASING  = 0b00100000;
        const ENCRYPTION         = 0b01000000;
    }
}

impl_serde_for_bitflags!(Capabilities);

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1 = 0x0210,
    Smb3_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Uuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Uuid {
    pub fn new(rng: &mut impl rand::Rng) -> Self {
        Self {
            data1: rng.gen(),
            data2: rng.gen(),
            data3: rng.gen(),
            data4: rng.gen(),
        }
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let to_hex = |v: &[u8]| {
            v.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        };
        format!(
            "{:08x}-{:04x}-{:04x}-{}-{}",
            self.data1,
            self.data2,
            self.data3,
            to_hex(&self.data4[..2]),
            to_hex(&self.data4[2..]),
        )
        .fmt(f)
    }
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Clone, Debug, PartialEq)]
#[repr(u16)]
#[serde(rename = "NegotiateContext$Pad4")]
pub enum NegotiateContext {
    Smb2PreauthIntegrityCapabilities(Smb2PreauthIntegrityCapabilities) = 1,
    Smb2EncryptionCapabilities(Smb2EncryptionCapabilities) = 2,
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum CipherId {
    Aes128Ccm = 1,
    Aes128Gcm = 2,
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum HashAlgorithm {
    Sha512 = 1,
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
pub struct Smb2PreauthIntegrityCapabilities {
    pub data_length: u16,
    pub reserved: u32,
    #[smb(collection(count(int_type = "u16", after = "reserved")))]
    pub hash_algorithms: Vec<HashAlgorithm>,
    #[smb(collection(count(int_type = "u16", after = "hash_algorithms_count")))]
    pub salt: Vec<u8>,
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
pub struct Smb2EncryptionCapabilities {
    pub data_length: u16,
    pub reserved: u32,
    #[smb(collection(count(int_type = "u16", after = "reserved")))]
    pub ciphers: Vec<CipherId>,
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 36)]
pub struct NegotiateRequest {
    pub security_mode: SecurityMode,
    pub reserved: u16,
    pub capabilities: Capabilities,
    pub client_guid: Uuid,
    #[smb(pad = 4, collection(count(int_type = "u16", after = "size")))]
    pub dialects: Vec<Dialect>,
    #[smb(collection(
        count(int_type = "u16", after = "client_guid"),
        offset(
            int_type = "u32",
            after = "client_guid",
            value = "HEADER_SIZE + 38 + self.dialects.len() * 2"
        )
    ))]
    pub negotiate_contexts: Vec<NegotiateContext>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Time {
    /// The number of 100-nanosecond intervals that have elapsed since January 1st 1601
    pub intervals: i64,
}

#[cfg(feature = "chrono")]
impl Time {
    pub fn to_date_time(&self) -> chrono::NaiveDateTime {
        use chrono::{
            naive::{NaiveDate, NaiveDateTime, NaiveTime},
            Duration,
        };
        let mut ts = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(1601, 1, 1).unwrap(),
            NaiveTime::from_hms_milli_opt(0, 0, 0, 0).unwrap(),
        );
        ts += Duration::microseconds(self.intervals / 10);

        let nanos = Duration::nanoseconds(self.intervals % 10 * 100);
        if self.intervals < 0 {
            ts -= nanos;
        } else {
            ts += nanos;
        }
        ts
    }
}

#[cfg(feature = "chrono")]
#[test]
fn time_to_date_time_positive() {
    use chrono::naive::{NaiveDate, NaiveDateTime, NaiveTime};
    let t = Time {
        intervals: 0x01d9fb8c14a5ee49,
    };
    // 2023-10-10 08:11:44.455226500 -0700
    let expected = NaiveDateTime::new(
        NaiveDate::from_ymd_opt(2023, 10, 10).unwrap(),
        NaiveTime::from_hms_nano_opt(8 + 7, 11, 44, 455226500).unwrap(),
    );
    assert_eq!(t.to_date_time(), expected);
}

#[cfg(feature = "chrono")]
#[test]
fn time_to_date_time_negative() {
    use chrono::naive::{NaiveDate, NaiveDateTime, NaiveTime};
    let t = Time {
        intervals: -0x40b122aff958,
    };
    // 1600-10-10 07:18:46.465297200 -0752
    let expected = NaiveDateTime::new(
        NaiveDate::from_ymd_opt(1600, 10, 10).unwrap(),
        NaiveTime::from_hms_nano_opt(8 + 7 + 1, 10, 46, 465297200).unwrap(),
    );
    assert_eq!(t.to_date_time(), expected);
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 65)]
pub struct NegotiateResponse {
    pub security_mode: SecurityMode,
    pub dialect: Dialect,
    pub server_guid: Uuid,
    pub capabilities: Capabilities,
    pub max_transaction_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub current_time: Time,
    pub boot_time: Time,
    #[smb(collection(
        count(int_type = "u16", after = "boot_time"),
        offset(int_type = "u16", after = "boot_time", value = "HEADER_SIZE + 64")
    ))]
    pub security_blob: Vec<u8>,
    #[smb(collection(
        count(int_type = "u16", after = "dialect"),
        offset(
            int_type = "u32",
            after = "security_blob_count",
            value = "HEADER_SIZE + 70 + self.security_blob.len()"
        )
    ))]
    pub negotiate_contexts: Vec<NegotiateContext>,
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 25)]
pub struct SessionSetupRequest {
    pub session_binding_request: bool,
    pub security_mode: SecurityMode,
    pub capabilities: Capabilities,
    pub channel: u32,
    pub previous_session_id: SessionId,
    #[smb(collection(
        count(int_type = "u16", after = "channel"),
        offset(int_type = "u16", after = "channel", value = "HEADER_SIZE + 24")
    ))]
    pub security_blob: Vec<u8>,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct SessionFlags: u16 {
        const GUEST    = 0b0000000000000001;
        const NULL     = 0b0000000000000010;
        const ENCRYPT  = 0b0000000000000100;
    }
}

impl_serde_for_bitflags!(SessionFlags);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 9)]
pub struct SessionSetupResponse {
    pub flags: SessionFlags,
    #[smb(collection(
        count(int_type = "u16", after = "flags"),
        offset(int_type = "u16", after = "flags", value = "HEADER_SIZE + 8")
    ))]
    pub security_blob: Vec<u8>,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct TreeConnectFlags: u16 {
        const CLUSTER_RECONNECT = 0b0000000000000001;
        const REDIRECT_TO_OWNER = 0b0000000000000010;
        const EXTENSION_PRESENT = 0b0000000000000100;
    }
}

impl_serde_for_bitflags!(TreeConnectFlags);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 9)]
pub struct TreeConnectRequest {
    pub flags: TreeConnectFlags,
    #[smb(collection(
        count(int_type = "u16", after = "flags", element_size = 2),
        offset(int_type = "u16", after = "flags", value = "HEADER_SIZE + 8")
    ))]
    pub path: String,
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum ShareType {
    Disk = 0x1,
    Pipe = 0x2,
    Print = 0x3,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct ShareFlags: u32 {
        const MANUAL_CACHING              = 0x00000000;
        const AUTO_CACHING                = 0x00000010;
        const VDO_CACHING                 = 0x00000020;
        const NO_CACHING                  = 0x00000030;
        const DFS                         = 0x00000001;
        const DFS_ROOT                    = 0x00000002;
        const RESTRICT_EXCLUSIVE_OPENS    = 0x00000100;
        const FORCE_SHARED_DELETE         = 0x00000200;
        const ALLOW_NAMESPACE_CACHING     = 0x00000400;
        const ACCESS_BASED_DIRECTORY_ENUM = 0x00000800;
        const FORCE_LEVELII_OPLOCK        = 0x00001000;
        const ENABLE_HASH_V1              = 0x00002000;
        const ENABLE_HASH_V2              = 0x00004000;
        const ENCRYPT_DATA                = 0x00008000;
        const IDENTITY_REMOTING           = 0x00040000;
        const COMPRESS_DATA               = 0x00100000;
        const ISOLATED_TRANSPORT          = 0x00200000;
    }
}

impl_serde_for_bitflags!(ShareFlags);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct ShareCapabilities: u32 {
        const DFS                     = 0x00000008;
        const CONTINUOUS_AVAILABILITY = 0x00000010;
        const SCALEOUT                = 0x00000020;
        const CLUSTER                 = 0x00000040;
        const ASYMMETRIC              = 0x00000080;
        const REDIRECT_TO_OWNER       = 0x00000100;
    }
}

impl_serde_for_bitflags!(ShareCapabilities);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct AccessMask: u32 {
        const FILE_READ_DATA         = 0x00000001;
        const FILE_WRITE_DATA        = 0x00000002;
        const FILE_APPEND_DATA       = 0x00000004;
        const FILE_EXECUTE           = 0x00000020;

        const FILE_LIST_DIRECTORY    = 0x00000001;
        const FILE_ADD_FILE          = 0x00000002;
        const FILE_ADD_SUBDIRECTORY  = 0x00000004;
        const FILE_TRAVERSE          = 0x00000020;
        const FILE_DELETE_CHILD      = 0x00000040;

        const FILE_READ_EA           = 0x00000008;
        const FILE_WRITE_EA          = 0x00000010;
        const FILE_READ_ATTRIBUTES   = 0x00000080;
        const FILE_WRITE_ATTRIBUTES  = 0x00000100;

        const DELETE                 = 0x00010000;
        const READ_CONTROL           = 0x00020000;
        const WRITE_DAC              = 0x00040000;
        const WRITE_OWNER            = 0x00080000;
        const SYNCHRONIZE            = 0x00100000;
        const ACCESS_SYSTEM_SECURITY = 0x01000000;
        const MAXIMUM_ALLOWED        = 0x02000000;
        const GENERIC_ALL            = 0x10000000;
        const GENERIC_EXECUTE        = 0x20000000;
        const GENERIC_WRITE          = 0x40000000;
        const GENERIC_READ           = 0x80000000;
    }
}

impl_serde_for_bitflags!(AccessMask);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 16)]
pub struct TreeConnectResponse {
    pub share_type: ShareType,
    pub share_flags: ShareFlags,
    pub share_capabilities: ShareCapabilities,
    pub access_mask: AccessMask,
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum OplockLevel {
    None = 0x00,
    II = 0x01,
    Exclusive = 0x08,
    Batch = 0x09,
    Lease = 0xFF,
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum ImpersonationLevel {
    Anonymous = 0x00000000,
    Identification = 0x00000001,
    Impersonation = 0x00000002,
    Delegate = 0x00000003,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct FileAttributes: u32 {
        const READONLY              = 0x00000001;
        const HIDDEN                = 0x00000002;
        const SYSTEM                = 0x00000004;
        const DIRECTORY             = 0x00000010;
        const ARCHIVE               = 0x00000020;
        const NORMAL                = 0x00000080;
        const TEMPORARY             = 0x00000100;
        const SPARSE_FILE           = 0x00000200;
        const REPARSE_POINT         = 0x00000400;
        const COMPRESSED            = 0x00000800;
        const OFFLINE               = 0x00001000;
        const NOT_CONTENT_INDEXED   = 0x00002000;
        const ENCRYPTED             = 0x00004000;
        const INTEGRITY_STREAM      = 0x00008000;
        const NO_SCRUB_DATA         = 0x00020000;
        const RECALL_ON_OPEN        = 0x00040000;
        const PINNED                = 0x00080000;
        const UNPINNED              = 0x00100000;
        const RECALL_ON_DATA_ACCESS = 0x00400000;
    }
}

impl_serde_for_bitflags!(FileAttributes);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct FileShareAccess: u32 {
        const READ   = 0x00000001;
        const WRITE  = 0x00000002;
        const DELETE = 0x00000004;
    }
}

impl_serde_for_bitflags!(FileShareAccess);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct FileCreateDisposition: u32 {
        const SUPERSEDE    = 0x00000000;
        const OPEN         = 0x00000001;
        const CREATE       = 0x00000002;
        const OPEN_IF      = 0x00000003;
        const OVERWRITE    = 0x00000004;
        const OVERWRITE_IF = 0x00000005;
    }
}

impl_serde_for_bitflags!(FileCreateDisposition);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct FileCreateOptions: u32 {
        const DIRECTORY_FILE            = 0x00000001;
        const WRITE_THROUGH             = 0x00000002;
        const SEQUENTIAL_ONLY           = 0x00000004;
        const NO_INTERMEDIATE_BUFFERING = 0x00000008;
        const SYNCHRONOUS_IO_ALERT      = 0x00000010;
        const SYNCHRONOUS_IO_NONALERT   = 0x00000020;
        const NON_DIRECTORY_FILE        = 0x00000040;
        const COMPLETE_IF_OPLOCKED      = 0x00000100;
        const NO_EA_KNOWLEDGE           = 0x00000200;
        const RANDOM_ACCESS             = 0x00000800;
        const DELETE_ON_CLOSE           = 0x00001000;
        const OPEN_BY_FILE_ID           = 0x00002000;
        const OPEN_FOR_BACKUP_INTENT    = 0x00004000;
        const NO_COMPRESSION            = 0x00008000;
        const OPEN_REMOTE_INSTANCE      = 0x00000400;
        const OPEN_REQUIRING_OPLOCK     = 0x00010000;
        const DISALLOW_EXCLUSIVE        = 0x00020000;
        const RESERVE_OPFILTER          = 0x00100000;
        const OPEN_REPARSE_POINT        = 0x00200000;
        const OPEN_NO_RECALL            = 0x00400000;
        const OPEN_FOR_FREE_SPACE_QUERY = 0x00800000;
    }
}

impl_serde_for_bitflags!(FileCreateOptions);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 57)]
pub struct CreateRequest {
    pub security_flags: u8,
    pub requested_oplock_level: OplockLevel,
    pub impersonation_level: ImpersonationLevel,
    pub create_flags: u64,
    pub reserved: u64,
    pub desired_access: AccessMask,
    pub file_attributes: FileAttributes,
    pub share_access: FileShareAccess,
    pub create_disposition: FileCreateDisposition,
    pub create_options: FileCreateOptions,
    #[smb(collection(
        count(int_type = "u16", after = "create_options", element_size = 2),
        offset(int_type = "u16", after = "create_options", value = "HEADER_SIZE + 56")
    ))]
    pub name: String,
    #[smb(collection(
        count(int_type = "u16", after = "name_count"),
        offset(
            int_type = "u16",
            after = "name_count",
            value = "HEADER_SIZE + 64 + self.name.len() * 2"
        )
    ))]
    pub create_contexts: Vec<u8>,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct FileCreateAction: u32 {
        const SUPERSEDED  = 0x00000000;
        const OPENED      = 0x00000001;
        const CREATED     = 0x00000002;
        const OVERWRITTEN = 0x00000003;
    }
}

impl_serde_for_bitflags!(FileCreateAction);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 89)]
pub struct CreateResponse {
    pub oplock_level: OplockLevel,
    pub reparse_point: bool,
    pub create_action: FileCreateAction,
    pub create_time: Time,
    pub last_access_time: Time,
    pub last_write_time: Time,
    pub change_time: Time,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: FileAttributes,
    pub reserved: u32,
    pub file_id: FileId,
    #[smb(collection(
        count(int_type = "u32", after = "file_id"),
        offset(int_type = "u32", after = "file_id", value = "HEADER_SIZE + 88")
    ))]
    pub create_contexts: Vec<u8>,
}

#[derive(SerializeWithDiscriminant, DeserializeWithDiscriminant, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum FileInformationClass {
    FileDirectoryInformation = 0x01,
    FileFullDirectoryInformation = 0x02,
    FileIdFullDirectoryInformation = 0x26,
    FileBothDirectoryInformation = 0x03,
    FileIdBothDirectoryInformation = 0x25,
    FileNamesInformation = 0x0C,
    FileIdExtdDirectoryInformation = 0x3C,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct QueryDirectoryFlags: u8 {
        const RESTART_SCANS = 0x01;
        const RETURN_SINGLE_ENTRY = 0x02;
        const INDEX_SPECIFIED = 0x04;
        const REOPEN = 0x10;
    }
}

impl_serde_for_bitflags!(QueryDirectoryFlags);

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 33)]
pub struct QueryDirectoryRequest {
    pub file_information_class: FileInformationClass,
    pub flags: QueryDirectoryFlags,
    pub file_index: u32,
    pub file_id: FileId,
    pub output_buffer_length: u32,
    #[smb(collection(
        count(int_type = "u16", after = "file_id", element_size = 2),
        offset(int_type = "u16", after = "file_id", value = "HEADER_SIZE + 32")
    ))]
    pub search_pattern: String,
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(size = 9)]
pub struct QueryDirectoryResponse<Body> {
    #[smb(collection(
        count(
            int_type = "u32",
            after = "size",
            value = "smb_size(&self.entries)",
            as_bytes = true
        ),
        offset(int_type = "u16", after = "size", value = "HEADER_SIZE + 8")
    ))]
    pub entries: Vec<QueryDirectoryEntry<Body>>,
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
#[smb(next_entry_offset = "align_to(smb_size(&self.body) + 4, 4)")]
pub struct QueryDirectoryEntry<Body> {
    pub body: Body,
}

impl<T> From<T> for QueryDirectoryEntry<T> {
    fn from(body: T) -> Self {
        QueryDirectoryEntry { body }
    }
}

#[derive(SerializeSmbStruct, DeserializeSmbStruct, Clone, Debug, PartialEq)]
pub struct FileIdBothDirectoryInformation {
    pub file_index: u32,
    pub creation_time: Time,
    pub last_access_time: Time,
    pub last_write_time: Time,
    pub change_time: Time,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    pub ea_size: u32,
    pub reserved: u32,
    pub file_id: u64,
    #[smb(collection(count(int_type = "u32", after = "file_attributes", element_size = 2)))]
    pub file_name: String,
}
