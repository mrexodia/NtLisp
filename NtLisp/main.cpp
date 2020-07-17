#include "crt/crt.h"
#include <ntifs.h>
#include "logger.hpp"
#include "driver_io.hpp"
extern "C"
{
#include <lisp.h>
}

// Global Lisp context.
//
static LispContext ctx;

// Device control handler.
//
static NTSTATUS device_control( PDEVICE_OBJECT device_object, PIRP irp )
{
    // If current control code is NTLUA_RUN:
    //
    PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation( irp );
    if ( irp_sp->Parameters.DeviceIoControl.IoControlCode == NTLISP_RUN )
    {
        const char* input = ( const char* ) irp->AssociatedIrp.SystemBuffer;
        ntlisp_result* result = ( ntlisp_result* ) irp->AssociatedIrp.SystemBuffer;

        size_t input_length = irp_sp->Parameters.DeviceIoControl.InputBufferLength;
        size_t output_length = irp_sp->Parameters.DeviceIoControl.OutputBufferLength;

        // Begin output size at 0.
        //
        irp->IoStatus.Information = 0;

        // If there is a valid, null-terminated buffer:
        //
        if ( input && input_length && input[ input_length - 1 ] == 0x0 )
        {
            // Execute the code in the buffer.
            //
            LispError error;
            Lisp program = lisp_read(input, &error, ctx);
            if (error == LISP_ERROR_NONE)
            {
                // execute program using global environment
                Lisp lisp_result = lisp_eval(program, &error, ctx);
                if (error == LISP_ERROR_NONE)
                {
                    // Print the result
                    lisp_print(lisp_result);

                    // Garbage collect
                    lisp_collect(lisp_make_null(), ctx);
                }
                else
                {
                    logger::error("lisp_eval error: %s\n", lisp_error_string(error));
                }
            }
            else
            {
                logger::error("lisp_read error: %s\n", lisp_error_string(error));
            }

            // Zero out the result.
            //
            result->errors = nullptr;
            result->outputs = nullptr;

            // Declare a helper exporting the buffer from KM memory to UM memory.
            //
            const auto export_buffer = [ ] ( logger::string_buffer& buf )
            {
                // Allocate user-mode memory to hold this buffer.
                //
                void* region = nullptr;
                size_t size = buf.iterator;
                ZwAllocateVirtualMemory( NtCurrentProcess(), ( void** ) &region, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                
                // Copy the buffer if allocation was succesful.
                //
                if ( region )
                {
                    __try
                    {
                        memcpy( region, buf.raw, buf.iterator );
                    }
                    __except ( 1 )
                    {

                    }
                }

                // Reset the buffer and return the newly allocated region.
                //
                buf.reset();
                return ( char* ) region;
            };

            // If we have a valid output buffer:
            //
            if ( output_length >= sizeof( ntlisp_result ) )
            {
                if ( logger::errors.iterator )
                    result->errors = export_buffer( logger::errors );
                if ( logger::logs.iterator )
                    result->outputs = export_buffer( logger::logs );
                irp->IoStatus.Information = sizeof( ntlisp_result );
            }

            // Reset logger buffers.
            //
            logger::errors.reset();
            logger::logs.reset();
        }

        // Declare success and return.
        //
        irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return STATUS_SUCCESS;
    }
    else
    {
        // Report failure.
        //
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return STATUS_UNSUCCESSFUL;
    }
}

// Unloads the driver.
//
static void unload_driver( PDRIVER_OBJECT driver )
{
    // Destroy the Lisp context.
    //
    lisp_shutdown(ctx);

    // Delete the symbolic link.
    //
    UNICODE_STRING sym_link;
    RtlInitUnicodeString( &sym_link, L"\\DosDevices\\NtLisp" );
    IoDeleteSymbolicLink( &sym_link );

    // Delete the device object.
    //
    if ( PDEVICE_OBJECT device_object = driver->DeviceObject )
        IoDeleteDevice( device_object );
}

// Execute corporate-level security check.
//
static NTSTATUS security_check( PDEVICE_OBJECT device_object, PIRP irp )
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

// Entry-point.
//
extern "C" NTSTATUS DriverEntry( DRIVER_OBJECT* DriverObject, UNICODE_STRING* RegistryPath )
{
    // Run static initializers.
    //
    crt::initialize();

    // Create a device object.
    //
    UNICODE_STRING device_name;
    RtlInitUnicodeString( &device_name, L"\\Device\\NtLisp" );

    PDEVICE_OBJECT device_object;
    NTSTATUS nt_status = IoCreateDevice
    (
        DriverObject,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_object 
    );
    if ( !NT_SUCCESS( nt_status ) )
        return nt_status;

    // Set callbacks.
    //
    DriverObject->DriverUnload = &unload_driver;
    DriverObject->MajorFunction[ IRP_MJ_CREATE ] = &security_check;
    DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = &security_check;
    DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = &device_control;
    
    // Create a symbolic link.
    //
    UNICODE_STRING dos_device;
    RtlInitUnicodeString( &dos_device, L"\\DosDevices\\NtLisp" );
    nt_status = IoCreateSymbolicLink( &dos_device, &device_name );
    if ( !NT_SUCCESS( nt_status ) )
    {
        IoDeleteDevice( device_object );
        return nt_status;
    }

    // Initialize Lisp.
    //
    ctx = lisp_init_lib();
    return STATUS_SUCCESS;
}