/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linenoise.h>
#include <string.h>
#include <array>
#include <iomanip>
#include <sys/user.h>
#include <algorithm>
#include <vector>

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

reg get_register_from_name(const string &name) {
    auto it = find_if(begin(g_register_descriptors), end(g_register_descriptors), [name](reg_descriptor rd) {return rd.name == name;});
    return it->r;
}

bool is_prefix(const string& prefix, const string& input) {
  if (prefix.size() > input.size()) return false;
  return equal(prefix.begin(), prefix.end(), input.begin());
}

class debugger {
public:
    debugger (pid_t pid): m_pid(pid) {
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

    void handle_sigtrap(siginfo_t info) {
        switch (info.si_code) {
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            cout << "hit a breakpoint at address 0x" << hex << get_pc() << endl;
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

    void print_pc_surroundings() {
        uint64_t pc = get_pc();
        uint64_t i;
        for (i=pc - 24; i <= pc + 24; i+=8) {
            cout << "0x" << hex << i << " : 0x" << hex << read_memory(i) << endl;
        }
    }
    
    void handle_command(const string& line) {
        vector<string> args = split (line, ' ');
        string command = args[0];

        if (is_prefix (command, "register") && (args[1] != "")) {
            if (is_prefix (args[1], "dump")) {
                dump_registers();
            } else if (is_prefix(args[1], "read")) {
                cout << get_register_value(m_pid, get_register_from_name(args[2])) << endl;
            } else if (is_prefix(args[1], "write")) {
                string val (args[3], 2);
                set_register_value(m_pid, get_register_from_name(args[2]), stol(val, 0, 16));
            }
        } else if (is_prefix(command,"special")) {
            print_pc_surroundings();
        } else if (is_prefix(command, "memory") && (args[1] != "")) {
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
    pid_t m_pid;
};


int main (int argc, char *argv[]) {
    if (argc<2) {
        cout << "Usage: second_debugger PID" << endl;
        exit(1);
    }
    
    pid_t pid = static_cast<pid_t>(stol(argv[1], 0, 10));
    ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    debugger *dbg = new debugger(pid);
    dbg->run();

    cout << "done" << endl;
    
}