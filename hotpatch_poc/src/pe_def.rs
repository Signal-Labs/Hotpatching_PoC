use std::pin::Pin;
use std::ptr::NonNull;
use std::slice;

use bitflags::bitflags;

// A parsed PE32+ structure (file format)
pub struct PE64File {
    raw_bytes: Vec<u8>,
    raw_base_address: usize,
    dos_header: NonNull<ImageDosHeader>,
    section_ptrs: Vec<SectionDescriptor>,
    data_directories: Vec<DataDirectoryDescriptor>,
}

pub struct SectionDescriptor {
    _raw_data_ptr: NonNull<*const u8>,
    _raw_data_size: usize,
    section_header: NonNull<SectionHeader>,
}

impl SectionDescriptor {
    fn new(_raw_data_ptr: NonNull<*const u8>, _raw_data_size: usize, section_header: NonNull<SectionHeader>) -> Self {
        Self {
            _raw_data_ptr,
            _raw_data_size,
            section_header,
        }
    }
    pub fn get_section_header_mut(&mut self) -> &mut SectionHeader {
        unsafe { self.section_header.as_mut() }
    }
    pub fn get_section_header(&self) -> &SectionHeader {
        unsafe { self.section_header.as_ref() }
    }
}

pub struct DataDirectoryDescriptor {
    _data_directory: NonNull<ImageDataDirectory>,
    data_directory_type: ImageDataDirectoryEntry,
    raw_data_table_ptr: NonNull<*const u8>,
    base_address: usize,
}

impl DataDirectoryDescriptor {
    fn _new(_data_directory: NonNull<ImageDataDirectory>, data_directory_type: ImageDataDirectoryEntry, raw_data_table_ptr: NonNull<*const u8>, base_address: usize) -> Self {
        Self {
            _data_directory,
            data_directory_type,
            raw_data_table_ptr,
            base_address,
        }
    }
    pub fn get_raw_data_table_ptr(&self) -> NonNull<*const u8> {
        self.raw_data_table_ptr
    }
    pub fn get_raw_table_offset(&self) -> usize {
        self.raw_data_table_ptr.as_ptr() as usize - self.base_address
    }
}

impl PE64File {
    pub fn new(raw_bytes: Vec<u8>) -> Pin<Box<Self>> {
        let res = PE64File {
            raw_bytes,
            raw_base_address: 0,
            dos_header: NonNull::dangling(),
            section_ptrs: Vec::new(),
            data_directories: Vec::new(),
        };
        let mut boxed = Box::pin(res);
        let dos_header = NonNull::from(unsafe { &*(boxed.raw_bytes.as_ptr() as *const _ as *const ImageDosHeader) });
        boxed.dos_header = dos_header;
        boxed.raw_base_address = boxed.raw_bytes.as_ptr() as usize;
        boxed
    }
    pub fn get_bytes<'a>(self: &'a Pin<Box<Self>>) -> &'a [u8] {
        &self.raw_bytes
    }
    pub fn get_dos_header<'a>(self: &'a Pin<Box<Self>>) -> &'a ImageDosHeader {
        unsafe { self.dos_header.as_ref() }
    }
    pub fn get_nt_headers<'a>(self: &Pin<Box<Self>>) -> &'a ImageNtHeaders64 {
        let dos_header = unsafe {core::ptr::read_unaligned(self.dos_header.as_ptr())};
        let nt_headers = (self.dos_header.as_ptr() as usize + dos_header.e_lfanew.0 as usize) as *const ImageNtHeaders64;
        unsafe { &*nt_headers }
    }
    pub fn _get_raw_base_address(self: &Pin<Box<Self>>) -> usize {
        self.raw_base_address
    }
    pub fn get_nt_headers_mut<'a>(self: &'a mut Pin<Box<Self>>) -> &'a mut ImageNtHeaders64 {
        let dos_header = unsafe {core::ptr::read_unaligned(self.dos_header.as_ptr())};
        let nt_headers = (self.dos_header.as_ptr() as usize + dos_header.e_lfanew.0 as usize) as *mut ImageNtHeaders64;
        unsafe { &mut *nt_headers }
    }
    pub fn get_sections_mut<'a>(self: &'a mut Pin<Box<Self>>) -> &'a mut Vec<SectionDescriptor> {
        &mut self.section_ptrs
    }
    pub fn parse_sections(self: &mut Pin<Box<Self>>) {
        if self.section_ptrs.len() > 0 {
            return;
        }
        let dos_header = unsafe {core::ptr::read_unaligned(self.dos_header.as_ptr())};
        let nt_headers = (self.dos_header.as_ptr() as usize + dos_header.e_lfanew.0 as usize) as *mut ImageNtHeaders64;
        let nt_headers = unsafe { &mut *nt_headers };
        let section_count = nt_headers.file_header.number_of_sections as usize;
        let optional_header_size = nt_headers.file_header.size_of_optional_header as usize;
        let section_header_size = core::mem::size_of::<SectionHeader>();
        let file_base = self.raw_base_address;
        // Section header is at the end of the optional header, we mostly use size_of() to calculate,
        // though we also use the optional header's size field in the Nt header.
        let section_header_ptr = (&self).dos_header.as_ptr() as usize +
            unsafe {self.dos_header.as_ref()}.e_lfanew.0 as usize + std::mem::size_of::<PESignature>() +
            std::mem::size_of::<ImageFileHeader>() + optional_header_size;
        // Collect `section_count` number of section headers
        let mut section_ptrs = Vec::new();
        for i in 0..section_count {
            let section_header = (section_header_ptr + (i * section_header_size)) as *const SectionHeader;

            let section_header = NonNull::new(section_header as
                *mut SectionHeader)
                .expect("Section header is null!");
            let raw_data_ptr = file_base + unsafe {section_header.as_ref()}.pointer_to_raw_data as usize;
            let section_descriptor = SectionDescriptor::new(
                NonNull::new(raw_data_ptr as *mut *const u8)
                    .expect("Section data pointer is null!"),
                unsafe { section_header.as_ref() }.size_of_raw_data as usize,
                section_header,
            );
            section_ptrs.push(section_descriptor);
        }
        self.section_ptrs = section_ptrs;
    }

    pub fn parse_data_directories(self: &mut Pin<Box<Self>>) {
        // Ensure section headers are parsed first
        self.parse_sections();
        if self.data_directories.len() > 0 {
            return;
        }
        let dos_header = unsafe {core::ptr::read_unaligned(self.dos_header.as_ptr())};
        let nt_headers = (self.dos_header.as_ptr() as usize + dos_header.e_lfanew.0 as usize) as *mut ImageNtHeaders64;
        let nt_headers = unsafe { &mut *nt_headers };
        let optional_header = &nt_headers.optional_header;
        let number_of_data_directories = optional_header.number_of_rva_and_sizes as usize;
        let mut data_directories = Vec::new();
        {
            for i in 0..number_of_data_directories {
                // get raw pointer to image_data_directory accounting for it being packed
                let data_directory_raw = ((optional_header as *const _ as usize) + std::mem::size_of::<ImageOptionalHeader64>() + (i * std::mem::size_of::<ImageDataDirectory>())) as *const ImageDataDirectory;
                let data_directory = unsafe { core::ptr::read_unaligned(data_directory_raw) };
                let data_directory_type = ImageDataDirectoryEntry::from_index(i)
                    .expect("Invalid data directory index!");
                // Find the section that contains the data directory
                let containing_section = self.section_ptrs.iter()
                    .find(|&section| {
                        let section_header = unsafe { section.section_header.as_ref() };
                        let section_start = section_header.virtual_address as usize;
                        let section_end = section_start + section_header.virtual_size as usize;
                        let data_directory_start = data_directory.virtual_address as usize;
                        let data_directory_end = data_directory_start + data_directory.size as usize;
                        data_directory_start >= section_start && data_directory_end < section_end
                    });
                let containing_section = match containing_section {
                    Some(section) => section,
                    None => {
                        // Data directory is not in any section, we ignore it
                        continue;
                    }
                };
                let data_table_offset = data_directory.virtual_address -
                    unsafe { containing_section.section_header.as_ref() }.virtual_address +
                    unsafe { containing_section.section_header.as_ref() }.pointer_to_raw_data;
                let data_table_raw_ptr = data_table_offset as usize + self.raw_base_address;
                let data_directory_descriptor = DataDirectoryDescriptor {
                    _data_directory: NonNull::new(data_directory_raw as *mut ImageDataDirectory)
                        .expect("Data directory is null!"),
                    data_directory_type,
                    raw_data_table_ptr: NonNull::new(data_table_raw_ptr as *mut *const u8)
                        .expect("Data table is null!"),
                    base_address: self.raw_base_address,
                };
                data_directories.push(data_directory_descriptor);
            };
        }
        self.data_directories = data_directories;
    }

    pub fn get_data_directory_mut<'a>(self: &'a mut Pin<Box<Self>>, data_directory_type: ImageDataDirectoryEntry) -> Option<&'a mut DataDirectoryDescriptor> {
        // Ensure data directories are parsed first
        self.parse_data_directories();
        self.data_directories.iter_mut()
            .find(|data_directory| data_directory.data_directory_type == data_directory_type)
    }
    pub fn get_data_directory<'a>(self: &'a mut Pin<Box<Self>>, data_directory_type: ImageDataDirectoryEntry) -> Option<&'a DataDirectoryDescriptor> {
        // Ensure data directories are parsed first
        self.parse_data_directories();
        self.data_directories.iter()
            .find(|data_directory| data_directory.data_directory_type == data_directory_type)
    }
}

/// A MS-DOS signature, e.g. "MZ"
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct ImageDosSignature(u16);


#[repr(packed)]
pub struct ImageDosHeader {
    pub e_magic: ImageDosSignature,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    // A offset from the module base to a ImageNtHeaders64 structure
    pub e_lfanew: RVA32<ImageNtHeaders64>,
}

#[repr(packed)]
pub struct ImageNtHeaders64 {
    pub signature: PESignature,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

// PEType is an enum representing pe32 or pe32+ identifiers
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum PEType {
    _PE32 = 0x10b,
    _PE64 = 0x20b,
}

// Define the ImageOptionalHeader64 structure
#[repr(packed)]
pub struct ImageOptionalHeader64 {
    pub magic: PEType,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA32<extern "C" fn()>,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: WindowsSubsystem,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // The data directory is an array of ImageDataDirectory structures
    // Its size is based on the number_of_rva_and_sizes field in this structure
    pub data_directory: [ImageDataDirectory;0],
}

// Load Configuration Directory from the PE32 format, e.g. IMAGE_LOAD_CONFIG_DIRECTORY
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LoadConfigurationDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u64,
    pub de_commit_total_free_threshold: u64,
    pub lock_prefix_table: u64,
    pub maximum_allocation_size: u64,
    pub virtual_memory_threshold: u64,
    pub process_affinity_mask: u64,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub reserved1: u16,
    pub edit_list: u64,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
    pub code_integrity: [u32;3],
    pub guard_address_taken_iat_entry_table: u64,
    pub guard_address_taken_iat_entry_count: u64,
    pub guard_long_jump_target_table: u64,
    pub guard_long_jump_target_count: u64,
    pub dynamic_value_reloc_table: u64,
    pub chpe_metadata_pointer: u64,
    pub guard_rf_failure_routine: u64,
    pub guard_rf_failure_routine_function_pointer: u64,
    pub dynamic_value_reloc_table_offset: u32,
    pub dynamic_value_reloc_table_section: u16,
    pub reserved2: u16,
    pub guard_rf_verify_stack_pointer_function_pointer: u64,
    pub hot_patch_table_offset: u32,
    pub reserved3: u32,
    pub enclave_configuration_pointer: u64,
    pub volatile_metadata_pointer: u64,
    pub guard_ehcontinuation_table: u64,
    pub guard_ehcontinuation_count: u64,
    pub guard_xfgcheck_function_pointer: u64,
    pub guard_xfgdispatch_function_pointer: u64,
    pub guard_xfgtable_dispatch_function_pointer: u64,
    pub cast_guard_os_determined_failure_mode: u64,
    pub guard_memcpy_function_pointer: u64,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct ImageHotPatchInfo {
    pub version: u32,
    pub size: u32,
    pub sequence_number: u32,
    pub base_image_list: u32,
    pub base_image_count: u32,
    // Version 2
    pub buffer_offset: u32,
    // Version 3
    pub extra_patch_size: u32,
}

#[derive(Copy,Clone,Default)]
#[repr(C)]
pub struct ImageHotPatchBase {
    pub sequence_number: u32,
    pub flags: u32,
    pub original_time_date_stamp: u32,
    pub original_checksum: u32,
    pub code_integrity_info: u32,
    pub code_integrity_size: u32,
    pub patch_table: u32,
    pub buffer_offset: u32,
}

// Define the ImageDataDirectory structure
#[derive(Clone)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}


// Define the ExportOrdinalTable which is an array of u16
#[derive(Clone)]
#[repr(C)]
pub struct ExportOrdinalTable {
    pub ordinals: [ExportAddressTableIndex;0],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExportAddressTableIndex(u16);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OrdinalTableIndex(u32);

// define the ExportAddressTableEntry which is a RVA32 to either a function or a string
#[derive(Clone)]
#[repr(transparent)]
pub struct ExportAddressTableEntry(pub RVA32<()>);

// Defines the ExportAddressTable
#[derive(Clone)]
#[repr(C)]
pub struct ExportAddressTable {
    // The export address table is an array of u32 values
    // Its size is based on the number_of_functions field in the ExportDirectoryTable
    pub entries: [ExportAddressTableEntry;0],
}

// enum representing the ImageDataDirectory entries
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum ImageDataDirectoryEntry {
    ExportTable = 0,
    ImportTable = 1,
    ResourceTable = 2,
    ExceptionTable = 3,
    CertificateTable = 4,
    BaseRelocationTable = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    TLSTable = 9,
    LoadConfigTable = 10,
    BoundImport = 11,
    IAT = 12,
    DelayImportDescriptor = 13,
    CLRRuntimeHeader = 14,
    Reserved = 15,
}

// impl ImageDataDirectoryEntry to convert a index into an enum
impl ImageDataDirectoryEntry {
    pub fn from_index(index: usize) -> Option<ImageDataDirectoryEntry> {
        match index {
            0 => Some(ImageDataDirectoryEntry::ExportTable),
            1 => Some(ImageDataDirectoryEntry::ImportTable),
            2 => Some(ImageDataDirectoryEntry::ResourceTable),
            3 => Some(ImageDataDirectoryEntry::ExceptionTable),
            4 => Some(ImageDataDirectoryEntry::CertificateTable),
            5 => Some(ImageDataDirectoryEntry::BaseRelocationTable),
            6 => Some(ImageDataDirectoryEntry::Debug),
            7 => Some(ImageDataDirectoryEntry::Architecture),
            8 => Some(ImageDataDirectoryEntry::GlobalPtr),
            9 => Some(ImageDataDirectoryEntry::TLSTable),
            10 => Some(ImageDataDirectoryEntry::LoadConfigTable),
            11 => Some(ImageDataDirectoryEntry::BoundImport),
            12 => Some(ImageDataDirectoryEntry::IAT),
            13 => Some(ImageDataDirectoryEntry::DelayImportDescriptor),
            14 => Some(ImageDataDirectoryEntry::CLRRuntimeHeader),
            15 => Some(ImageDataDirectoryEntry::Reserved),
            _ => None,
        }
    }
    // Convert an enum into a usize index
    pub fn _to_index(&self) -> usize {
        match self {
            ImageDataDirectoryEntry::ExportTable => 0,
            ImageDataDirectoryEntry::ImportTable => 1,
            ImageDataDirectoryEntry::ResourceTable => 2,
            ImageDataDirectoryEntry::ExceptionTable => 3,
            ImageDataDirectoryEntry::CertificateTable => 4,
            ImageDataDirectoryEntry::BaseRelocationTable => 5,
            ImageDataDirectoryEntry::Debug => 6,
            ImageDataDirectoryEntry::Architecture => 7,
            ImageDataDirectoryEntry::GlobalPtr => 8,
            ImageDataDirectoryEntry::TLSTable => 9,
            ImageDataDirectoryEntry::LoadConfigTable => 10,
            ImageDataDirectoryEntry::BoundImport => 11,
            ImageDataDirectoryEntry::IAT => 12,
            ImageDataDirectoryEntry::DelayImportDescriptor => 13,
            ImageDataDirectoryEntry::CLRRuntimeHeader => 14,
            ImageDataDirectoryEntry::Reserved => 15,
        }
    }
}

// enum representing valid Windows Subsystem values
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum WindowsSubsystem {
    _ImageSubsystemUnknown = 0,
    _ImageSubsystemNative = 1,
    _ImageSubsystemWindowsGui = 2,
    _ImageSubsystemWindowsCui = 3,
    _ImageSubsystemOs2Cui = 5,
    _ImageSubsystemPosixCui = 7,
    _ImageSubsystemNativeWindows = 8,
    _ImageSubsystemWindowsCeGui = 9,
    _ImageSubsystemEfiApplication = 10,
    _ImageSubsystemEfiBootServiceDriver = 11,
    _ImageSubsystemEfiRuntimeDriver = 12,
    _ImageSubsystemEfiRom = 13,
    _ImageSubsystemXbox = 14,
    _ImageSubsystemWindowsBootApplication = 16,
}


bitflags! {
    /// The `SectionCharacteristics` bitflags are used to describe the characteristics of a section.
    pub struct SectionCharacteristics: u32 {
        const IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
        const IMAGE_SCN_CNT_CODE = 0x00000020;
        const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        const IMAGE_SCN_LNK_OTHER = 0x00000100;
        const IMAGE_SCN_LNK_INFO = 0x00000200;
        const IMAGE_SCN_LNK_REMOVE = 0x00000800;
        const IMAGE_SCN_LNK_COMDAT = 0x00001000;
        const IMAGE_SCN_GPREL = 0x00008000;
        const IMAGE_SCN_MEM_PURGEABLE = 0x00020000;
        const IMAGE_SCN_MEM_16BIT = 0x00020000;
        const IMAGE_SCN_MEM_LOCKED = 0x00040000;
        const IMAGE_SCN_MEM_PRELOAD = 0x00080000;
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        const IMAGE_SCN_MEM_READ = 0x40000000;
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}


#[derive(Clone)]
#[repr(C)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: SectionCharacteristics,
}

#[derive(Clone)]
#[repr(packed)]
pub struct ImageFileHeader {
    pub machine: ImageFileMachine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}


// An enum representing valid ImageFileMachine values
#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum ImageFileMachine {
    // All possible Machine Types
    _Unknown = 0x0,
    _Am33 = 0x1d3,
    _Amd64 = 0x8664,
    _Arm = 0x1c0,
    _Arm64 = 0xaa64,
    _ArmNT = 0x1c4,
    _Ebc = 0xebc,
    _I386 = 0x14c,
    _Ia64 = 0x200,
    _M32R = 0x9041,
    _Mips16 = 0x266,
    _MipsFpu = 0x366,
    _MipsFpu16 = 0x466,
    _PowerPC = 0x1f0,
    _PowerPCFP = 0x1f1,
    _R4000 = 0x166,
    _RiscV32 = 0x5032,
    _RiscV64 = 0x5064,
    _RiscV128 = 0x5128,
    _SH3 = 0x1a2,
    _SH3DSP = 0x1a3,
    _SH4 = 0x1a6,
    _SH5 = 0x1a8,
    _Thumb = 0x1c2,
    _WceMipsV2 = 0x169,

}

#[derive(Copy,Clone)]
#[repr(transparent)]
pub struct PESignature(u32);


// RVA32 is a relative virtual address to an underlying type
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct RVA32<T: ?Sized>(pub u32, pub core::marker::PhantomData<T>);

// impl RVA32 with a function that adds the usize base_address and then dereferences the pointer
impl<T> RVA32<T> {
    pub fn _get(&self, base_address: usize) -> &T {
        unsafe { &*((base_address + self.0 as usize) as *const T) }
    }

    pub fn _get_mut(&mut self, base_address: usize) -> &mut T {
        unsafe { &mut *((base_address + self.0 as usize) as *mut T) }
    }
}



#[derive(Copy,Clone, Debug)]
#[repr(C)]
pub struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

impl UnicodeString {
    // Convert the buffer to a utf16 string based on the length field
    pub fn _extract_string(&self) -> Option<String> {
        if self.length == 0 || self.buffer as *const _ as usize == 0 {
            return None;
        }
        let slice = unsafe {
            slice::from_raw_parts(self.buffer, self.length as usize / 2)
        };
        // Convert slice to a String
        core::char::decode_utf16(slice.iter().cloned()).collect::<Result<String, _>>().ok()
    }
}

#[derive(Clone)]
pub struct UnicodeStringWrapper {
    pub string: UnicodeString,
    pub buffer: Vec<u16>,
}

impl UnicodeStringWrapper {

    /// Create a new unicodestring from an existing rust &str
    pub fn new(string: &str) -> Self {
        let buffer = string.encode_utf16().collect::<Vec<u16>>();
        let length = buffer.len() * 2;
        let unistr = UnicodeString {
            length: length as u16,
            maximum_length: length as u16,
            buffer: buffer.as_ptr(),
        };
        Self {
            string: unistr,
            buffer,
        }
    }
}
