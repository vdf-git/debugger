#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h> 
#include <sys/ptrace.h>
#include <string>
#include <linenoise.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <string.h>
#include <sys/user.h>
#include <algorithm>
#include <iomanip>
#include "libelfin/elf/elf++.hh"
#include "libelfin/dwarf/dwarf++.hh"

using namespace std;

enum class reg {
    rax, rbx, rcx, rdx,
    rdi, rsi, rbp, rsp,
    r8, r9, r10, r11,
    r12, r13, r14, r15,
    rip, rflags, cs, orig_rax,
    fs_base, gs_base, fs, gs,
    ss, ds, es
};

constexpr size_t n_regs = 27;

struct reg_descriptor {
    reg r;
    int dwarf_r;
    string name;
};

const array<reg_descriptor, n_regs> g_register_descriptors {{
    {reg::r15, 15, "r15"},
    {reg::r14, 14, "r14"},
    {reg::r13, 13, "r13"},
    {reg::r12, 12, "r12"},
    {reg::rbp, 6, "rbp"},
    {reg::rbx, 3, "rbx"},
    {reg::r11, 11, "r11"},
    {reg::r10, 10, "r10"},
    {reg::r9, 9, "r9"},
    {reg::r8, 8, "r8"},
    {reg::rax, 0, "rax"},
    {reg::rcx, 2, "rcx"},
    {reg::rdx, 1, "rdx"},
    {reg::rsi, 4, "rsi"},
    {reg::rdi, 5, "rdi"},
    {reg::orig_rax, -1, "orig_rax"},
    {reg::rip, -1, "rip"},
    {reg::cs, 51, "cs"},
    {reg::rflags, 49, "eflags"},
    {reg::rsp, 7, "rsp"},
    {reg::ss, 52, "ss"},
    {reg::fs_base, 58, "fs_base"},
    {reg::gs_base, 59, "gs_base"},
    {reg::ds, 53, "ds"},
    {reg::es, 50, "es"},
    {reg::fs, 54, "fs"},
    {reg::gs, 55, "gs"},
}};

vector<string> split(const string &s, char delim) {
    vector<string> out{};
    stringstream ss{s};
    string item;

    while (getline(ss, item, delim)) {
        out.push_back(item);
    }

    return out;
}

uint64_t get_register_value (pid_t pid, reg r) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    auto it = find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](reg_descriptor rd) {return rd.r == r;});
    
    return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors)));
}

void set_register_value (pid_t pid, reg r, uint64_t value) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    auto it = find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](reg_descriptor rd) { return rd.r == r;});
    
    *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))) = value;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}
 
uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum) {
    auto it = find_if(begin(g_register_descriptors), end(g_register_descriptors), [regnum](reg_descriptor rd) {return rd.dwarf_r == regnum;});
    if (it == end(g_register_descriptors) ) {
        throw out_of_range("Unknown dwarf register");
    }
    
    return get_register_value(pid, it->r);
}

string get_register_name(reg r) {
    auto it = find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](reg_descriptor rd) {return rd.r == r;});
    return it->name;
}

reg get_register_from_name(const string &name) {
    auto it = find_if(begin(g_register_descriptors), end(g_register_descriptors), [name](reg_descriptor rd) {return rd.name == name;});
    return it->r;
}

bool is_prefix(const string& prefix, const string& input) {
  if (prefix.size() > input.size()) return false;
  return equal(prefix.begin(), prefix.end(), input.begin());
}


class breakpoint {
public:
    breakpoint(pid_t pid, intptr_t addr)
        : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{}
    {}
    breakpoint() {}
        
    void enable() {
        auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, NULL);
        m_saved_data = static_cast<uint8_t>(data & 0xff);
        uint64_t int3 = 0xcc;
        uint64_t data_with_int3 = ((data & ~0xff) | int3);
        ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

        m_enabled = true;
    }

    void disable() {
        auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, NULL);
        auto restored_data = ((data & ~0xff) | m_saved_data);
        ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

        m_enabled = false;
    }

    auto is_enabled() const -> bool { return m_enabled;}
    auto get_address() const -> intptr_t{return m_addr;}

private:
    pid_t m_pid;
    intptr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data;
};
 
   
class debugger {
public:
    debugger (string prog_name, pid_t pid): m_prog_name{move(prog_name)}, m_pid(pid) {
        auto fd = open(m_prog_name.c_str(), O_RDONLY);
        
        m_elf = elf::elf(elf::create_mmap_loader(fd));
        m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
    }

    dwarf::die get_function_from_pc(uint64_t pc) {
        for (auto &cu : m_dwarf.compilation_units()) {
            if (die_pc_range(cu.root()).contains(pc)) {
                for (const auto &die : cu.root()) {
                    if (die.tag == dwarf::DW_TAG::subprogram) {
                        if (die_pc_range(die).contains(pc)) {
                            return die;
                        }
                    }
                }
            }
        }
        throw out_of_range("Cannot find function");
    }
    
    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc) {
        for (auto &cu: m_dwarf.compilation_units()) {
            if (die_pc_range(cu.root()).contains(pc)) {
                auto &lt = cu.get_line_table();
                auto it = lt.find_address(pc);
                if (it == lt.end()) {
                    throw out_of_range("cannot find line entry");
                }
                else {
                    return it;
                }
            }
        }
    }
    
    void print_source(const string& file_name, unsigned line, unsigned n_lines_context) {
        ifstream file (file_name);
        
        auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
        auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;
        
        char c;
        auto current_line = 1u;
        
        while (current_line != start_line && file.get(c)) {
            if (c == '\n') {
                ++current_line;
            }
        }
        
        cout << (current_line == line ? "> " : "  ");
        
        while (current_line <= end_line && file.get(c)) {
            cout << c;
            if (c == '\n') {
                ++current_line;
                cout << (current_line == line ? "> " : "  ");
            }
        }
        cout << endl;
    }
    
    siginfo_t get_signal_info() {
        siginfo_t info;
        ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
        return info;
    }

    void run() {
        int wait_status;
        int options = 0;
        waitpid(m_pid, &wait_status, options);

        char *line = NULL;
        while ((line = linenoise("my_dbg> ")) != NULL) {
            if (strcmp(line, "")) {
                handle_command(line);
                linenoiseHistoryAdd(line);
                linenoiseFree(line);
            }
        }
    }

    void continue_execution() {
        step_over_breakpoint();
        ptrace(PTRACE_CONT, m_pid, NULL, NULL);
        wait_for_signal();
    }

    void set_breakpoint_at_address(intptr_t addr) {
        cout << "set breakpoint at 0x" << hex << addr << endl;
        breakpoint bp {m_pid, addr};
        bp.enable();
        m_breakpoints[addr] = bp;
    }

    void dump_registers() {
        for (const auto& rd : g_register_descriptors) {
            cout << rd.name << " 0x" << setfill('0') << setw(16) << hex << get_register_value(m_pid, rd.r) << endl;
        }
    }

    uint64_t read_memory(uint64_t address) {
        return ptrace(PTRACE_PEEKDATA, m_pid, address, NULL);
    }

    void write_memory(uint64_t address, uint64_t value) {
        ptrace(PTRACE_POKEDATA, m_pid, address, value);
    }

    uint64_t get_pc() {
        return get_register_value(m_pid, reg::rip);
    }

    void set_pc(uint64_t pc) {
        set_register_value(m_pid, reg::rip, pc);
    }

    void step_over_breakpoint() {
        if (m_breakpoints.count(get_pc())) {
            auto &bp = m_breakpoints[get_pc()]; 

            if (bp.is_enabled()) {
                bp.disable();
                ptrace(PTRACE_SINGLESTEP, m_pid, NULL, NULL);
                wait_for_signal();
                bp.enable();
            }
        }
    }

    void handle_sigtrap(siginfo_t info) {
        switch (info.si_code) {
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            set_pc(get_pc() - 1);
            cout << "hit a breakpoint at address 0x" << hex << get_pc() << endl;
            auto line_entry = get_line_entry_from_pc(get_pc());
            print_source(line_entry->file->path, line_entry->line, 0);
            return;
        }
        case TRAP_TRACE:
            return;
        default:
            cout << "unknown SIGTRAP code" << info.si_code << endl;
            return;
        }
    }

    void wait_for_signal() {
        int wait_status;
        auto options = 0;
        waitpid(m_pid, &wait_status, options);
        
        auto siginfo = get_signal_info();
        
        switch (siginfo.si_signo) {
        case SIGTRAP:
            handle_sigtrap(siginfo);
            break;
        case SIGSEGV:
            cout << "WAAHAE! SEGFAULT!!! Reason: " << siginfo.si_code << endl;
            break;
        default:
            cout << "Got signal " << strsignal(siginfo.si_signo) << endl;
        }
    }

    void handle_command(const string& line) {
        vector<string> args = split (line, ' ');
        string command = args[0];

        if (is_prefix (command, "continue")) {
            continue_execution();
        } else if (is_prefix (command, "break")) {
            string addr (args[1], 2);
            set_breakpoint_at_address(stol(addr, 0 , 16)); 
        } else if (is_prefix (command, "register") && (args[1] != "")) {
            if (is_prefix (args[1], "dump")) {
                dump_registers();
            } else if (is_prefix(args[1], "read")) {
                cout << get_register_value(m_pid, get_register_from_name(args[2])) << endl;
            } else if (is_prefix(args[1], "write")) {
                string val (args[3], 2);
                set_register_value(m_pid, get_register_from_name(args[2]), stol(val, 0, 16));
            }
        } else if (is_prefix(command, "memory") && (args[1] == "")) {
            string addr {args[2], 2};
            if (is_prefix (args[1], "read")) {
                cout << hex << read_memory(stol(addr, 0, 16)) << endl;
            } else if (is_prefix(args[1], "write")) {
                string val {args[3], 2};
                write_memory(stol(addr, 0, 16), stol(val, 0, 16));
            }
        } else {
            printf("Unknown command\n");
        }
    }

private:
    string m_prog_name;
    pid_t m_pid;
    unordered_map<intptr_t,breakpoint> m_breakpoints;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
};


int main(int argc, char *argv[]) {
    breakpoint bp {5, 321};
  if (argc <2) {
    printf("Program not specified\n");
    exit(1);
  }

  char* prog = argv[1];
  int pid = fork();
  if (!pid) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl(prog, prog, NULL);
  } else {
    debugger dbg(prog, pid);
    dbg.run();
  }
}
