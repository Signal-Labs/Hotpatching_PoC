
use std::io::{Seek, Write};
use crate::pe_def::{ImageHotPatchBase, ImageHotPatchInfo, ImageDataDirectory, ImageDataDirectoryEntry, ImageDosHeader, ImageNtHeaders64, ImageOptionalHeader64, LoadConfigurationDirectory, PE64File, SectionCharacteristics, UnicodeString, UnicodeStringWrapper};
use windows::Win32::System::Registry::RegGetValueW;
use windows::Win32;
use windows::Win32::System::Registry::REG_VALUE_TYPE;
use core::ffi::c_void;
use std::fs::File;
use std::pin::Pin;
use windows::core::PCWSTR;
mod pe_def;


type NTSTATUS = u32;


#[derive(Copy, Clone)]
#[repr(C)]
struct load_hotpatch_info {
    version: u32,
    hotpatch_path: UnicodeString,
    sid: [u8;68],
    target_checksum: u32,
    target_timedatestamp: u32,
}

#[link(name = "ntdll")]
extern "C" {
    fn NtManageHotPatch(hotpatch_class:u32, info: *mut u8, infolen: u32, retlen: *mut u32) -> NTSTATUS;
}



fn check_enable_hotpatch() -> bool {
    let mut value:u32 = 0;
    let mut value_type = REG_VALUE_TYPE(0);
    let mut value_size = std::mem::size_of::<u32>() as u32;
    let key = Win32::System::Registry::HKEY_LOCAL_MACHINE;
    let subkey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\0\0";
    let value_name = "EnableHotPatch\0\0";
    let subkey_wide: Vec<u16> = subkey.encode_utf16().collect();
    let value_name_wide: Vec<u16> = value_name.encode_utf16().collect();
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::from_raw(subkey_wide.as_ptr() ),
            PCWSTR::from_raw(value_name_wide.as_ptr()),
            Win32::System::Registry::RRF_RT_REG_DWORD,
            Some(&mut value_type),
            Some(&mut value as *mut u32 as *mut _ as *mut c_void),
            Some(&mut value_size),
        )
    };
    if status.is_ok() {
        value != 0
    } else {
        false
    }
}

fn enable_hotpatch() -> bool {
    let key = Win32::System::Registry::HKEY_LOCAL_MACHINE;
    let subkey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\0\0";
    let value_name = "EnableHotPatch\0\0";
    let subkey_wide: Vec<u16> = subkey.encode_utf16().collect();
    let value_name_wide: Vec<u16> = value_name.encode_utf16().collect();
    let value:u32 = 0x1000;
    let status = unsafe {
        Win32::System::Registry::RegSetKeyValueW(
            key,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            PCWSTR::from_raw(value_name_wide.as_ptr()),
            Win32::System::Registry::REG_DWORD.0,
            Some(&value as *const u32 as *const _ as *const c_void),
            std::mem::size_of::<u32>() as u32,
        )
    };
    status.is_ok()
}

fn adjust_privs() {
    // Lookup the LUID for the SeLoadDriverPrivilege
    let mut luid = Win32::Foundation::LUID::default();
    let mut name = "SeLoadDriverPrivilege\0\0".encode_utf16().collect::<Vec<u16>>();
    unsafe {
        let res = Win32::Security::LookupPrivilegeValueW(
            None,
            PCWSTR::from_raw(name.as_mut_ptr()),
            &mut luid,
        );
        if !res.as_bool() {
            println!("Failed to lookup privilege value");
            std::process::exit(1);
        }
    }
    // Create a TOKEN_PRIVILEGES struct with the LUID and SE_PRIVILEGE_ENABLED
    let mut tp = Win32::Security::TOKEN_PRIVILEGES::default();
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = Win32::Security::SE_PRIVILEGE_ENABLED;
    // Adjust the token privileges
    let mut token = Win32::Foundation::HANDLE::default();
    println!("Adjusting privs\n");
    unsafe {
        let res = Win32::System::Threading::OpenProcessToken(
            Win32::System::Threading::GetCurrentProcess(),
            Win32::Security::TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        );
        if !res.as_bool() {
            println!("Failed to open process token");
            std::process::exit(1);
        }
        let res = Win32::Security::AdjustTokenPrivileges(
            token,
            false,
            Some(& tp),
            std::mem::size_of::<Win32::Security::TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );
        if !res.as_bool() {
            println!("Failed to adjust token privileges, ensure we're running as administrator");
            std::process::exit(1);
        }
    }
}
// Target file to create the Hotpatch for
const TARGET_PE: &'static str = "C:\\Windows\\System32\\kernelbase.dll";
// Compile file to use as the Hotpatch, such as the compiled `hotpatch_replace_vs` file
const HOTPATCH_PE: &'static str = "C:\\Code\\kernelbase_patch.dll";
// Modified Hotpatch file to create and pass to the kernel
const HOTPATCH_MOD_PE: &'static str = "C:\\Code\\kernelbase_patch_mod.dll";
// Same path as above, but prepended with DosDevices
const HOTPATCH_MOD_PE_NT: &'static str = "\\DosDevices\\C:\\Code\\kernelbase_patch_mod.dll";
fn main() {
    // We'll need to be able to adjust privileges to enable hotpatching. Note this isn't required
    // for applying a patch within our own process.
    adjust_privs();
    let is_enabled = check_enable_hotpatch();
    if !is_enabled {
        println!("Hotpatching is not currently enabled. enter 'enable' to enable it, or 'quit' to exit");
        let mut input = String::new();
        let enabled: bool;
        loop {
            std::io::stdin().read_line(&mut input).unwrap();
            if input.trim() == "enable" {
                enabled = enable_hotpatch();
                break;
            } else if input.trim() == "quit" {
                enabled = false;
                break;
            }
            input.clear();
        }
        if !enabled {
            println!("Hotpatching not enabled (or failed to enable), exiting");
            std::process::exit(1);
        } else {
            println!("Enabled hotpatching, reboot required to take effect");
            std::process::exit(0);
        }
    }
    println!("Reading hotpatch target: {}", TARGET_PE);
    let (checksum, timedatestamp) = get_hotpatch_target(TARGET_PE);
    println!("Creating hotpatch {} for target {} with the patch in {}",
             HOTPATCH_MOD_PE, TARGET_PE, HOTPATCH_PE);
    create_hotpatch_pe(HOTPATCH_PE, HOTPATCH_MOD_PE, checksum, timedatestamp);
    // Loop reading user input until the user enters the string "go"
    let mut input = String::new();
    println!("Enter 'go' to run the hotpatched PE");
    loop {
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim() == "go" {
            break;
        }
        input.clear();
    }
    // User entered 'go', lets continue by triggering the hotpatch load
    let hotpatch_class = 0; // Loads a new hotpatch
    let hotpatch_mod_nt = UnicodeStringWrapper::new(HOTPATCH_MOD_PE_NT);
    let hotpatch_info = load_hotpatch_info {
        version: 2,
        hotpatch_path: hotpatch_mod_nt.string,
        sid: [0;68],
        target_checksum: checksum,
        target_timedatestamp: timedatestamp,
    };
    let info = &hotpatch_info as *const load_hotpatch_info as *mut u8;
    let infolen = std::mem::size_of::<load_hotpatch_info>() as u32;
    let mut retlen = 0;

    let status = unsafe { NtManageHotPatch(hotpatch_class, info, infolen, &mut retlen) };
    match status {
        0 => println!("Hotpatch loaded successfully"),
        _ => {
            if status == 0xc00000bb {
                println!("Status returned STATUS_NOT_SUPPORTED, this can happen for multiple reasons");
            } else {
                println!("Hotpatch failed to load with status {:#x}", status)
            }
        },
    }
}

/// Gets the checksum and timestamp of the target PE, required for creating a hotpatch
fn get_hotpatch_target(file: &str) -> (u32, u32) {
    println!("Generating PoC hotpatch for {}", file);
    // Read the entire `TARGET_PE` file into a buffer
    let target_file = std::fs::read(file).unwrap();
    // Note: Must ensure target_file is not dropped while we work with its raw pointers/castings
    // below.
    // Interpret the target_file as a DOS header
    let dos_header_base = unsafe { &mut *(target_file.as_ptr() as *mut ImageDosHeader) };

    let pe_header_base = {
        let nt_headers = (target_file.as_ptr() as usize + dos_header_base.e_lfanew.0 as usize) as *mut ImageNtHeaders64;
        unsafe { &mut *nt_headers }
    };

    // Save the checksum as we'll use it when creating the hotpatch
    let checksum = pe_header_base.optional_header.check_sum;
    let timedatestamp = pe_header_base.file_header.time_date_stamp;
    (checksum, timedatestamp)
}

fn write_bytes<T>(file: &mut std::fs::File, bytes: &T) {
    let sliced_bytes = unsafe { std::slice::from_raw_parts(bytes as *const T as *const u8,
                                                           std::mem::size_of::<T>()) };
    file.write_all(sliced_bytes).expect("Failed to write bytes to file");
}

/// Creates a hotpatch PE file by reading `patch_pe` and writing it to `hotpatch_pe` for the target
/// `checksum` and `timedatestamp`
fn create_hotpatch_pe(patch_pe: &str, hotpatch_pe: &str, checksum: u32, timedatestamp: u32) {
    // Read the HOTPATCH_PE into a buffer
    let hotpatch_file_nomod = std::fs::read(patch_pe).unwrap();
    let mut pe64_file = PE64File::new(hotpatch_file_nomod);
    // Create the `HOTPATCH_PE` file
    let mut hotpatch_file = std::fs::File::create(hotpatch_pe).unwrap();
    // Parse the sections & data directories from the HOTPATCH_PE
    PE64File::parse_sections(&mut pe64_file);
    PE64File::parse_data_directories(&mut pe64_file);

    // Get the offset we'll use for the hotpatch table, which will be the end of the current file
    // As the offset is a u32, this would panic if the file is larger than 4GB.
    let new_hotpatch_offset_file:u32 = PE64File::get_bytes(&pe64_file).len().try_into().unwrap();

    // We need to convert this to an RVA, so we need to add the offset to the virtual address of the
    // section that'll contain it, we'll do this later


    // Update size of image
    {
        let nt_headers = PE64File::get_nt_headers_mut(&mut pe64_file);
        nt_headers.optional_header.size_of_image += std::mem::size_of::<ImageHotPatchInfo>() as u32;
        nt_headers.optional_header.size_of_image += std::mem::size_of::<ImageHotPatchBase>() as u32;
    }

    // Create our own hotpatch header
    let mut hotpatch_hdr = ImageHotPatchInfo::default();
    // Lets use version 3
    hotpatch_hdr.version = 3;
    // Set size to its minimum required, which is the size of the ImageHotPatchInfo + 4 * base_image_count + pad bytes
    let pad_bytes: usize = 4;
    hotpatch_hdr.size = std::mem::size_of::<ImageHotPatchInfo>() as u32 + 4 + (pad_bytes as u32) + std::mem::size_of::<ImageHotPatchBase>() as u32;
    // Set sequence to 1, as we're expecting this to be the first patch
    hotpatch_hdr.sequence_number = 1;
    // This patch applies to a single base image
    hotpatch_hdr.base_image_count = 1;
    // hotpatch_hdr.base_image_list + &hotpatch_hdr = u32 offset arrays to ImageHotPatchBase entries
    // as per https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/struct.IMAGE_HOT_PATCH_BASE.html
    // We put the list immediately after the ImageHotPatchInfo, we do add pad bytes.
    hotpatch_hdr.base_image_list = std::mem::size_of::<ImageHotPatchInfo>() as u32;
    // First, we need to create the ImageHotPatchBase entry
    let mut hotpatch_base = ImageHotPatchBase::default();
    // originalchecksum & original timedatestamp in hotpatch_base must match the optional_header checksum & timestamp
    // of the target PE we want to patch
    hotpatch_base.original_checksum = checksum;
    hotpatch_base.original_time_date_stamp = timedatestamp;
    println!("Checksum: {}, TimeDateStamp: {}", checksum, timedatestamp);
    hotpatch_base.sequence_number = 1;
    // Garbage values for now.
    hotpatch_base.buffer_offset = 0;
    hotpatch_base.patch_table = 0;
    hotpatch_base.buffer_offset = 0;

    // Determine which section our hotpatch will be in, and update the section header accordingly
    let mut found_section = false;
    for section in PE64File::get_sections_mut(&mut pe64_file) {
        let section_hdr = section.get_section_header_mut();
        // Compare offsets of the section header to the hotpatch table offset, if the hotpatch table
        // starts at the end of the section, we've identified the section we want to patch. There
        // should not be any section that starts at our hotpatch offset, as our offset is at
        // the end of the file.
        if section_hdr.pointer_to_raw_data as usize +
            section_hdr.size_of_raw_data as usize == new_hotpatch_offset_file as usize {
            // Calculate the RVA of the hotpatch table
            let new_hotpatch_offset = section_hdr.virtual_address + section_hdr.size_of_raw_data;
            println!("Section start: 0x{:x}, end: 0x{:x}, pointer_to_raw_data:{:#x}, size_of_raw_data:{:#x}", section_hdr.virtual_address, section_hdr.virtual_address + section_hdr.virtual_size, section_hdr.pointer_to_raw_data, section_hdr.size_of_raw_data);
            // We have our target section, update its size
            section_hdr.size_of_raw_data += std::mem::size_of::<ImageHotPatchInfo>() as u32;
            section_hdr.size_of_raw_data += std::mem::size_of::<ImageHotPatchBase>() as u32;
            if section_hdr.characteristics.contains(SectionCharacteristics::IMAGE_SCN_MEM_DISCARDABLE) {
                // If the section is discardable, we need to make it non-discardable
                section_hdr.characteristics.remove(SectionCharacteristics::IMAGE_SCN_MEM_DISCARDABLE);
                section_hdr.characteristics.insert(SectionCharacteristics::IMAGE_SCN_MEM_READ);
            }
            if section_hdr.virtual_size < section_hdr.size_of_raw_data {
                // If the section's virtual size is less than its raw size, we hackily update the
                // virtual size to match the raw size + the size of the hotpatch table, really we
                // should be placing our table in a new section or updating a more relevant section.
                section_hdr.virtual_size = section_hdr.size_of_raw_data;
                section_hdr.virtual_size += std::mem::size_of::<ImageHotPatchInfo>() as u32;
                section_hdr.virtual_size += std::mem::size_of::<ImageHotPatchBase>() as u32;
            }
            println!("Section start: 0x{:x}, end: 0x{:x}, pointer_to_raw_data:{:#x}, size_of_raw_data:{:#x}", section_hdr.virtual_address, section_hdr.virtual_address + section_hdr.virtual_size, section_hdr.pointer_to_raw_data, section_hdr.size_of_raw_data);
            {
                // Get the load config table
                let load_config_descriptor =
                    PE64File::get_data_directory_mut(
                        &mut pe64_file,
                        ImageDataDirectoryEntry::LoadConfigTable)
                        .expect("Load Config Table not found");

                // Get the load config table from the descriptor
                let load_config_table = unsafe {
                    load_config_descriptor.get_raw_data_table_ptr().cast::<LoadConfigurationDirectory>().as_mut()
                };

                // Check that the current image has no hotpatch table, as we don't support appending or replacing
                // hotpatches
                assert_eq!(load_config_table.hot_patch_table_offset, 0);
                load_config_table.hot_patch_table_offset = new_hotpatch_offset;
            }

            found_section = true;
            break;
        }
    }
    assert_eq!(found_section, true, "Failed to find section to patch");

    write_out_pe(&mut hotpatch_file, &mut pe64_file, &hotpatch_hdr, &hotpatch_base, new_hotpatch_offset_file, pad_bytes);

}

fn write_out_pe(hotpatch_file: &mut File, pe64_file: &mut Pin<Box<PE64File>>, hotpatch_hdr: &ImageHotPatchInfo, hotpatch_base: &ImageHotPatchBase, new_hotpatch_offset_file: u32, pad_bytes: usize) {
    let load_config_table = unsafe {
        // Get the load config table
        let load_config_descriptor =
            PE64File::get_data_directory(
                pe64_file,
                ImageDataDirectoryEntry::LoadConfigTable)
                .expect("Load Config Table not found");
        load_config_descriptor.get_raw_data_table_ptr().cast::<LoadConfigurationDirectory>().as_ref()
    };
    let dos_header = PE64File::get_dos_header(pe64_file);
    let nt_headers = PE64File::get_nt_headers(pe64_file);
    // First we write the dos header
    write_bytes(hotpatch_file, dos_header);
    // Determine any padding between the DOS header and the PE header
    let e_lfanew = dos_header.e_lfanew.0;
    let current_pos_tmp = hotpatch_file.stream_position().unwrap() as usize;
    let padding = e_lfanew as usize - current_pos_tmp;
    // Write the padding, copying it from the target file
    if padding > 0 {
        let hotpatch_file_nomod = PE64File::get_bytes(pe64_file);
        let padding_bytes = &hotpatch_file_nomod[current_pos_tmp..e_lfanew as usize];
        hotpatch_file.write_all(padding_bytes).unwrap();
    }

    // Write the PE header
    write_bytes(hotpatch_file, nt_headers);

    // Write the data directories, we copy these from the target file
    {
        let hotpatch_file_nomod = PE64File::get_bytes(pe64_file);
        let current_offset = hotpatch_file.stream_position().unwrap() as usize;
        let number_of_directories = nt_headers.optional_header.number_of_rva_and_sizes as usize;
        let bytes_to_get = number_of_directories * std::mem::size_of::<ImageDataDirectory>();
        let data_directory_bytes = &hotpatch_file_nomod[current_offset..current_offset + bytes_to_get];
        hotpatch_file.write_all(data_directory_bytes).unwrap();
    }
    // If the size of the optional header is larger than what we wrote, we need to write the
    // remaining bytes
    {
        let hotpatch_file_nomod = PE64File::get_bytes(pe64_file);
        let current_offset = hotpatch_file.stream_position().unwrap() as usize;
        let optional_header_size = nt_headers.file_header.size_of_optional_header as usize;
        let data_directory_size = nt_headers.optional_header.number_of_rva_and_sizes as usize * std::mem::size_of::<ImageDataDirectory>();
        let remaining_bytes = (std::mem::size_of::<ImageOptionalHeader64>() + data_directory_size) - optional_header_size;
        let remaining_bytes = &hotpatch_file_nomod[current_offset..current_offset + remaining_bytes];
        hotpatch_file.write_all(remaining_bytes).unwrap();
    }

    // Write the section headers
    for section in PE64File::get_sections_mut(pe64_file) {
        let section_hdr = section.get_section_header();
        println!("Section start: 0x{:x}, end: 0x{:x}, pointer_to_raw_data:{:#x}, size_of_raw_data:{:#x}", section_hdr.virtual_address, section_hdr.virtual_address + section_hdr.virtual_size, section_hdr.pointer_to_raw_data, section_hdr.size_of_raw_data);
        write_bytes(hotpatch_file, section_hdr);
    }
    // Write the remaining bytes until we reach the load config table offset
    let load_config_offset = {
        // Get the load config table
        let load_config_descriptor =
            PE64File::get_data_directory(
                pe64_file,
                ImageDataDirectoryEntry::LoadConfigTable)
                .expect("Load Config Table not found");
        load_config_descriptor.get_raw_table_offset()
    };
    let current_offset = hotpatch_file.stream_position().unwrap() as usize;
    let hotpatch_file_nomod = PE64File::get_bytes(pe64_file);
    let remaining_bytes = &hotpatch_file_nomod[current_offset..load_config_offset as usize];
    hotpatch_file.write(remaining_bytes).unwrap();
    // Write the load config table
    write_bytes(hotpatch_file, load_config_table);
    // Write the remaining bytes until we reach the hotpatch table offset
    let current_offset = hotpatch_file.stream_position().unwrap() as usize;

    let remaining_bytes = &hotpatch_file_nomod[current_offset..new_hotpatch_offset_file as usize];
    hotpatch_file.write(remaining_bytes).unwrap();
    // Write the hotpatch table
    write_bytes(hotpatch_file, hotpatch_hdr);
    // Write padding bytes
    // We only support 4
    assert!(pad_bytes == 4);
    // The pad bytes will be the offset entry, this will be sizeof hotpatchinfo + sizeof pad
    let offset_val:u32 = std::mem::size_of::<ImageHotPatchInfo>() as u32 + std::mem::size_of::<u32>() as u32;
    let offset_val = offset_val.to_le_bytes();
    hotpatch_file.write(&offset_val).unwrap();
    write_bytes(hotpatch_file, hotpatch_base);
    println!("Finished writing hotpatched file!");
}

