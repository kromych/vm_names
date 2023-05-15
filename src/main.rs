use anyhow::Result;
use windows::core::BSTR;
use windows::core::HSTRING;
use windows::Win32::Foundation::DISP_E_TYPEMISMATCH;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Com::CoInitializeEx;
use windows::Win32::System::Com::CoInitializeSecurity;
use windows::Win32::System::Com::CoUninitialize;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::COINIT_MULTITHREADED;
use windows::Win32::System::Com::EOAC_NONE;
use windows::Win32::System::Com::RPC_C_AUTHN_LEVEL_DEFAULT;
use windows::Win32::System::Com::RPC_C_IMP_LEVEL_IMPERSONATE;
use windows::Win32::System::Com::VARIANT;
use windows::Win32::System::Ole::VarFormat;
use windows::Win32::System::Ole::VariantClear;
use windows::Win32::System::Ole::VARFORMAT_FIRST_DAY_SYSTEMDEFAULT;
use windows::Win32::System::Ole::VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT;
use windows::Win32::System::Wmi::IWbemClassObject;
use windows::Win32::System::Wmi::IWbemLocator;
use windows::Win32::System::Wmi::IWbemServices;
use windows::Win32::System::Wmi::WbemLocator;
use windows::Win32::System::Wmi::WBEM_E_NOT_FOUND;
use windows::Win32::System::Wmi::WBEM_FLAG_FORWARD_ONLY;
use windows::Win32::System::Wmi::WBEM_FLAG_RETURN_IMMEDIATELY;

fn get_row_item(o: &IWbemClassObject, name: &str) -> Result<Option<String>> {
    let mut value: VARIANT = Default::default();
    let name_hstr = HSTRING::from(name);
    unsafe {
        if let Err(e) = o.Get(&name_hstr, 0, &mut value, None, None) {
            if e.code().0 == WBEM_E_NOT_FOUND.0 {
                return Ok(None);
            } else {
                anyhow::bail!(e);
            }
        }

        let bstr = VarFormat(
            &value,
            None,
            VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
            VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
            0,
        );
        if let Err(e) = &bstr {
            if e.code().0 == DISP_E_TYPEMISMATCH.0 {
                return Ok(None);
            } else {
                anyhow::bail!(e.to_owned());
            }
        }

        VariantClear(&mut value)?;
        Ok(Some(String::from_utf16(bstr?.as_wide())?))
    }
}

struct ComHandle {
    _per_thread_dummy: std::marker::PhantomData<()>,
}

impl ComHandle {
    pub fn new() -> windows::core::Result<ComHandle> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)?;
            CoInitializeSecurity(
                PSECURITY_DESCRIPTOR::default(),
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            )?;
        }
        Ok(Self {
            _per_thread_dummy: std::marker::PhantomData,
        })
    }
}

impl Drop for ComHandle {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

struct ComHyperV<'a> {
    _per_thread_dummy: &'a ComHandle,
    server: IWbemServices,
    _locator: IWbemLocator,
}

impl<'a> ComHyperV<'a> {
    pub fn new(com_handle: &'a ComHandle) -> windows::core::Result<ComHyperV> {
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)? };
        let server = unsafe {
            locator.ConnectServer(
                &BSTR::from("root\\virtualization\\v2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )?
        };

        Ok(Self {
            _per_thread_dummy: com_handle,
            server,
            _locator: locator,
        })
    }

    fn vm_names(&self, str_query: &str) -> windows::core::Result<Vec<String>> {
        let mut names = Vec::new();
        unsafe {
            let query = self.server.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(str_query),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?;

            let mut row = [None; 1];
            let mut returned = 0;

            while query.Next(-1, &mut row, &mut returned).is_ok() {
                if returned == 0 {
                    break;
                }
                if let Some(row) = &row[0] {
                    if let Ok(Some(name)) = get_row_item(row, "ElementName") {
                        names.push(name)
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        Ok(names)
    }

    pub fn running_vm_names(&self) -> windows::core::Result<Vec<String>> {
        self.vm_names("SELECT ElementName FROM Msvm_ComputerSystem WHERE Caption = \"Virtual Machine\" AND EnabledState = 2")
    }

    pub fn all_vm_names(&self) -> windows::core::Result<Vec<String>> {
        self.vm_names(
            "SELECT ElementName FROM Msvm_ComputerSystem WHERE Caption = \"Virtual Machine\"",
        )
    }
}

fn main() -> Result<()> {
    let com = ComHandle::new().unwrap();
    let hyperv = ComHyperV::new(&com).unwrap();

    println!("Running VMs: {:?}", hyperv.running_vm_names()?);
    println!("All VMs: {:?}", hyperv.all_vm_names()?);

    Ok(())
}
