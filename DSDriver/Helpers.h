#include "Device.h"

/*----------------------------------------
	Indirect Type Definitions
----------------------------------------*/
typedef void (*PFUNC)(IN LONGLONG Arg1, IN LONGLONG Arg2);

/*----------------------------------------
	Assembly Functions
----------------------------------------*/
VOID AsmTest(VOID);

/*----------------------------------------
    General Functions
----------------------------------------*/
VOID
PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars);

VOID
Open_Close_File();
