// cSpell:enableCompoundWords
// cSpell:words hakorlib dword cmovl qword movss movaps

use std::io::Write;
use hakorlib::*;
use std::process::exit;
use std::collections::HashMap;
use std::io;

const PROCESS_NAME: &str = "FarCry5.exe";
const MODULE_NAME: &str = "FC_m64.dll";



#[derive(Clone)]
enum HackType {
    Nop,
    Change,
    Jump,
}



#[derive(Clone)]
struct TargetHacks {
    offset: u64,
    method: HackType,
    toggled: bool,
    cave_addr: u64,
    target_bytes: Vec<u8>,
    modified_bytes: Vec<u8>,
    shellcode: Vec<u8>,
}



impl TargetHacks {
    fn new_nop(offset: u64, target_bytes: Vec<u8>) -> TargetHacks {
        TargetHacks {
            offset,
            method: HackType::Nop,
            toggled: false,
            cave_addr: 0,
            target_bytes,
            modified_bytes: vec!(),
            shellcode: vec!(),
        }
    }

    fn new_modify(offset: u64, target_bytes: Vec<u8>, modified_bytes: Vec<u8>) -> TargetHacks {
        TargetHacks {
            offset,
            method: HackType::Change,
            toggled: false,
            cave_addr: 0,
            target_bytes,
            modified_bytes,
            shellcode: vec!(),
        }
    }

    fn new_jmp(offset: u64, target_bytes: Vec<u8>, shellcode: Vec<u8>) -> TargetHacks {
        TargetHacks {
            offset,
            method: HackType::Jump{},
            toggled: false,
            cave_addr: 0,
            target_bytes,
            modified_bytes: vec!(),
            shellcode,
        }
    }
}



fn main() {
    let process_id = find_pid_by_name(PROCESS_NAME).unwrap_or_else(|e| {println!("{}",e); exit(1)});                        //get process pid
    let base_addr = get_module_base_by_name(process_id, MODULE_NAME).unwrap_or_else(|e| {println!("{}",e); exit(2)});       //get target module base addr
    let process_handle = get_handle_all(process_id).unwrap_or_else(|e| {println!("{}",e); exit(3)});                        //get full privilege handle to target process
    let mut hack_list = construct_hacks(base_addr);

    display_hacks(&mut hack_list);
    let mut exit_flag = false;
    while !exit_flag {
        let input = get_input();
        if hack_list.contains_key(&input) {
            let hack = hack_list.get_mut(&input).unwrap();
            match hack.method {
                HackType::Nop => hack.toggled = toggle_nop(process_handle, base_addr, hack.offset, &mut hack.target_bytes).unwrap_or_else(|e| {println!("{}",e); exit(5)}),
                HackType::Change => hack.toggled = toggle_modify(process_handle, base_addr, hack.offset, &mut hack.target_bytes, &mut hack.modified_bytes).unwrap_or_else(|e| {println!("{}",e); exit(6)}),
                HackType::Jump => hack.toggled = toggle_jmp(process_handle, base_addr, hack.offset, &mut hack.target_bytes, &mut hack.cave_addr, &mut hack.shellcode).unwrap_or_else(|e| {println!("{}",e); exit(7)}),
            };
            display_hacks(&mut hack_list);
        } else {
            if input == "help".to_string() {print_help()}
            else if input == "exit".to_string() {exit_flag = true} 
            else {println!("{} isn't valid input.", input)}
        }
    }
    println!("exiting");
    exit(0)
}



fn construct_hacks(base_addr: u64) -> HashMap<String,TargetHacks>{
    let mut hack_list = HashMap::new();
    hack_list.insert("god_mode".to_string(), TargetHacks::new_nop(0x86AB0B4, vec!(0xFF, 0x50, 0x30)));  //call qword prt [rax+30]
    hack_list.insert("inf_throwables".to_string(), TargetHacks::new_nop(0xAD8CFA6, vec!(0x29, 0x57, 0x4C)));    //sub [rdi+4C],edx
    hack_list.insert("no_recoil".to_string(), TargetHacks::new_modify(0x19E8CE4, vec!(
                                                                                    0xF3, 0x0F, 0x11, 0x70, 0x38,                   //movss [rax+38],xmm6
                                                                                    0x0F, 0x28, 0xB4, 0x24, 0xB0, 0x00, 0x00, 0x00, //movaps xmm6,[rsp+000000B0]
                                                                                    0xF3, 0x44, 0x0F, 0x11, 0x50, 0x3C,             //movss [rax+3C],xmm10
                                                                                ),
                                                                                vec!(
                                                                                    0x90, 0x90, 0x90, 0x90, 0x90,                   //nop x5
                                                                                    0x0F, 0x29, 0xB4, 0x24, 0xB0, 0x00, 0x00, 0x00, //movaps xmm6,[rsp+000000B0]
                                                                                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,             //nop x6
                                                                                )));
    let mut mag_hack = TargetHacks::new_jmp(0xA92DDF5, 
                                        vec!(
                                            0x41, 0x89, 0xF8,                                               //mov r8d,edi
                                            0x44, 0x0F, 0x4C, 0xC0,                                         //cmovl r8d,eax
                                            0x44, 0x89, 0x83, 0x88, 0x01, 0x00, 0x00,                       //mov [rbx+00000188],r8d
                                        ),                               
                                        vec!(
                                            0x41, 0x89, 0xF8,                                               //mov r8d,edi
                                            0x44, 0x0F, 0x4C, 0xC0,                                         //cmovl r8d,eax
                                            0x83, 0xBB, 0x88, 0x00, 0x00, 0x00, 0x00,                       //cmp dword ptr [rbx+00000088],00
                                            0x74, 0x0A,                                                     //je +9
                                            0xC7, 0x83, 0x88, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     //mov [rbx+00000188],00000000
                                            0x85, 0xFF,                                                     //test edi,edi
                                        ));
    for byte in create_jmp(base_addr+mag_hack.offset+mag_hack.target_bytes.len() as u64).unwrap_or_else(|e| {println!("{}",e); exit(4)}) {
        mag_hack.shellcode.push(byte)
    }
    hack_list.insert("mag_hack".to_string(), mag_hack);
    hack_list
}



fn get_input() -> String {
    print!("$");
    io::stdout().flush().unwrap();
    let mut guess = String::new();
    io::stdin()
        .read_line(&mut guess)
        .unwrap_or_else(|e| {println!("{}",e); exit(5)});
    guess.trim().to_string()

}



fn display_hacks(hack_list: &mut HashMap<String, TargetHacks>) {
    println!("\x1B[2J\x1B[1;1H");
    for hack in hack_list {
        println!("{}: {}", hack.0, hack.1.toggled)
    }
}



fn print_help(){
    println!("enter the name of a hack to toggle it.\nenter \"exit\" to exit.\nenter \"help\" for this message");
}