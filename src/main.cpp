#include "memory/memory.h"
#include "syscalls/syscalls.h"
#include "util.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <vector>

// memory useage exmaple below the exe is notpad if u cant read 
int main()
{
	if (!Syscalls::Init())
	{
		std::puts("ntdll syscall ids failed"); //fucked the syscall ids 
		Util::Pause();
		return 1;
	}

	Memory proc;
	if (!proc.Attach("notepad.exe"))
	{
		std::puts("[-] could not attach to notepad"); // run notepad dont be gay
		Util::Pause();
		return 1;
	}

	const std::vector<Module> modules = proc.ListModules();
	const uint64_t base = proc.GetBase();
	const size_t size = proc.ModuleSize(base);

	std::puts("[+] notepad");
	std::printf("  pid       %" PRIu32 "\n", proc.GetPid());
	std::printf("  handle    %p\n", proc.GetHandle());
	std::printf("  base      0x%016" PRIX64 "\n", base);
	std::printf("  image     %zu bytes (%.2f MiB)\n", size, size / (1024.0 * 1024.0));
	
	// this the list of modules loads inside notepad u can remove it looks kinda messy it js cool  
	std::printf("  modules   %zu\n\n", modules.size());

	for (const Module& mod : modules)
		std::printf("  %-32s 0x%016" PRIX64 " %zu bytes\n", mod.Name, mod.Base, mod.Size);

	Util::Pause();
	return 0;
}
