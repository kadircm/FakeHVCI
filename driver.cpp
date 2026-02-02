#include <ntddk.h>
#include <intrin.h> // __readcr0 ve __writecr0 için şart

// Derleyicinin tip tanımlarını anlaması için
typedef unsigned __int64 uintptr_t;

extern "C" {
    // Prototip tanımı
    BOOLEAN MmIsHvciEnabled();

    VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
        UNREFERENCED_PARAMETER(DriverObject);
        DbgPrint("[-] HVCI Spoof Driver durduruldu.\n");
    }

    NTSTATUS PatchHVCI(BOOLEAN fakeStatus) {
        // Fonksiyonun adresini al
        // Not: Bu isim ntoskrnl.lib içinde yoksa linker hata verir.
        // Eğer hata alırsan bu satırı MmGetSystemRoutineAddress ile değiştirmeliyiz.
        PVOID pFunc = (PVOID)MmIsHvciEnabled;
        
        if (!pFunc) {
            DbgPrint("[-] MmIsHvciEnabled adresi bulunamadi.\n");
            return STATUS_NOT_FOUND;
        }

        // Yazma korumasını (CR0.WP) geçici olarak devre dışı bırak
        KIRQL irql = KeRaiseIrqlToDpcLevel();
        unsigned __int64 cr0 = __readcr0();
        __writecr0(cr0 & ~0x10000); // WP (Write Protect) bitini temizle

        // Patch: mov al, [01 veya 00]; ret
        // 0xB0 = mov al, imm8
        // 0xC3 = ret
        unsigned char patch[] = { 0xB0, (unsigned char)(fakeStatus ? 0x01 : 0x00), 0xC3 };
        
        RtlCopyMemory(pFunc, patch, sizeof(patch));

        // Korumayı geri yükle
        __writecr0(cr0);
        KeLowerIrql(irql);

        DbgPrint("[+] MmIsHvciEnabled basariyla yamalandi (Status: %d).\n", fakeStatus);
        return STATUS_SUCCESS;
    }

    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
        UNREFERENCED_PARAMETER(RegistryPath);
        
        DriverObject->DriverUnload = DriverUnload;

        DbgPrint("[*] HVCI Spoofing baslatiliyor...\n");
        return PatchHVCI(TRUE); 
    }
}
