#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <string>
#include <linenoise.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <iostream>
#include <string.h>

using namespace std;

class breakpoint {
public:
    breakpoint(pid_t pid, intptr_t addr)
        : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{}
    {}
    breakpoint() {}
        
    void enable();
    void disable();

    auto is_enabled() const -> bool { return m_enabled;}
    auto get_address() const -> intptr_t{return m_addr;}

private:
    pid_t m_pid;
    intptr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data;
};

void breakpoint::enable() {
  auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, NULL);
  m_saved_data = static_cast<uint8_t>(data & 0xff);
  uint64_t int3 = 0xcc;
  uint64_t data_with_int3 = ((data & ~0xff) | int3);
  ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

  m_enabled = true;
}

void breakpoint::disable() {
  auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, NULL);
  auto restored_data = ((data & ~0xff) | m_saved_data);
  ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

  m_enabled = false;
}

bool is_prefix(const string& prefix, const string& input) {
  if (prefix.size() > input.size()) return false;
  return equal(prefix.begin(), prefix.end(), input.begin());
}

class debugger {
public:
  debugger (string prog_name, pid_t pid)
    : m_prog_name{move(prog_name)}, m_pid(pid) {}
      
  void run();
  void continue_execution();
  void set_breakpoint_at_address(intptr_t addr);
  void handle_command(const string&);
  
private:
  string m_prog_name;
  pid_t m_pid;
  unordered_map<intptr_t,breakpoint> m_breakpoints;
};

void debugger::set_breakpoint_at_address(intptr_t addr) {
    cout << "set breakpoint at 0x" << hex << addr << endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::continue_execution() {
  ptrace(PTRACE_CONT, m_pid, NULL, NULL);

  int wait_status;
  int options = 0;
  waitpid(m_pid, &wait_status, options);
}

vector<string> split(const string &s, char delim) {
  vector<string> out{};
  stringstream ss{s};
  string item;

  while (getline(ss, item, delim)) {
    out.push_back(item);
  }

  return out;
}

void debugger::handle_command(const string& line) {

    vector<string> args = split (line, ' ');
    string command = args[0];

    if (is_prefix (command, "continue")) {
        continue_execution();
    } else if (is_prefix (command, "break")) {
        string addr (args[1], 2);
        set_breakpoint_at_address(stol(addr, 0 , 16)); 
    } else {
        printf("Unknown command\n");
    }
}

void debugger::run() {
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
