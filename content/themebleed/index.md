+++
title = "CVE-2023-38146: Arbitrary Code Execution via Windows Themes"
date = 2023-09-13
[extra]
author = "gabe_k"
logo = "rt.svg"
+++

This is a fun bug I found while poking around at weird Windows file formats. It's a kind of classic Windows style vulnerability featuring broken signing, sketchy DLL loads, file races, cab files, and Mark-of-the-Web silliness. It was also my first experience submitting to the MSRC Windows bug bounty since leaving Microsoft in April of 2022.

In the great tradition of naming vulnerabilities, I've lovingly named this one ThemeBleed (no logo as of yet but I'm accepting submissions.)

Overall it was a lot of fun finding and PoC-ing this vulnerability, and MSRC was incredibly fast in responding and judging it for bounty :^]

> Below is a slightly modified version of the report I sent to Microsoft. After the report is a timeline and my notes on their fix.

## Summary

A series of issues exist on Windows 11 which can lead to arbitrary code being executed when a user loads a `.theme` file.

## Bug Details

### 1. Background

On Windows, `.theme` files allow customization of the OS appearance. The `.theme` files themselves are ini files, which contain configuration details. Clicking on a `.theme` file on Windows 11 will invoke the following command:

```
"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\themecpl.dll,OpenThemeAction <theme file path>
```
This vulnerability specifically deals with the handling of `.msstyles` files. These are PE (DLL) files that contain resources such as icons to be used in a theme, but (should) contain no code. A `.msstyles` file can be referenced in a `.theme` file in the following way:
```
[VisualStyles]
Path=%SystemRoot%\resources\Themes\Aero\Aero.msstyles
```

When the `.theme` file is opened, the `.msstyles` file will also be loaded.

### 2. The "Version 999" Check

When loading a `.msstyles` file, the `LoadThemeLibrary` in `uxtheme.dll` will check the version of the theme. It will do this by loading the resource named `PACKTHEM_VERSION` from the binary. If the version it reads is 999, it will then call into another function `ReviseVersionIfNecessary`. A decompiled version of this function with the relevant parts commented can be seen below:

```c
__int64 __fastcall LoadThemeLibrary(const WCHAR *msstyles_path, HMODULE *out_module, int *out_version)
{
  HMODULE module_handle;
  signed int result;
  int version;
  signed int return_val;
  unsigned int resource_size;
  __int16 *version_ptr;

  if ( out_version )
    *out_version = 0;
  module_handle = LoadLibraryExW(msstyles_path, 0, 2u);
  if ( !module_handle )
    return (unsigned int)MakeErrorLast();
  result = GetPtrToResource(
             module_handle,
             L"PACKTHEM_VERSION",
             (const unsigned __int16 *)1,
             (void **)&version_ptr,
             &resource_size); // !!! [1] version number is extracted from resource "PACKTHEM_VERSION"
  if ( result < 0 || resource_size != 2 )
    goto LABEL_22;
  version = *version_ptr;
  if ( out_version )
    *out_version = version;
  return_val = -2147467259;
  if ( version >= 4 )
  {
    if ( version > 4 )
      result = -2147467259;
    return_val = result;
  }
  if ( return_val < 0 && (_WORD)version == 999 ) // !!! [2] special case for version 999
  {
    resource_size = 999;
    return_val = ReviseVersionIfNecessary(msstyles_path, 999, (int *)&resource_size); // !!! [3] call to `ReviseVersionIfNecessary`
...
}
```

### 3. Time-of-Check-Time-of-Use in ReviseVersionIfNecessary Allows Signature Bypass

The `ReviseVersionIfNecessary` function which is called by the previous step performs several actions. Given a path to a `.msstyles` file, it will perform the following:

1. Create a new file path by appending `_vrf.dll` to the `.msstyles` file path.
2. Check if this new `_vrf.dll` file exists. If not, exit.
3. Open the `_vrf.dll` file
4. Verify the signature on the `_vrf.dll` file. If the signature is invalid, exit.
5. Close the `_vrf.dll` file
6. Load the `_vrf.dll` file as a DLL and call the `VerifyThemeVersion` function.

The goal of this appears to be to attempt to safely load a signed DLL and call a function. This implementation is flawed however, because the DLL is closed after verifying the signature in step 5, and then re-opened when the DLL is loaded via a call to LoadLibrary in step 6. This provides a race window between those two steps where an attacker may replace the `_vrf.dll` file that has had its signature verified, with a malicious one that is not signed. That malicious DLL will then be loaded and executed.

### 4. Mark-of-the-Web Bypass

If a user downloads a `.theme` file, upon launching it they will receive a security warning due to the presence of Mark-of-the-Web on the file. It turns out this can be bypassed by packaging the `.theme` file in a `.themepack` file.

A `.themepack` file is a cab file containing a `.theme` file. When a `.themepack` file is opened, the contained `.theme` file will be loaded. When opening a `.themepack` file with Mark-of-the-Web, no warning is displayed, so the warning that would normally be seen is bypassed.

## Proof of Concept

I developed a PoC for this issue. The PoC consists of two components, an SMB server executable to be run on an attacker's machine, and a `.theme` file to be opened on the target's machine.

I chose to use an attacker controlled SMB server for this because a `.theme` file may point to a `.msstyle` path on a remote SMB share. Since the SMB share is attacker controlled, it can easily exploit the TOCTOU bug in `ReviseVersionIfNecessary` by returning a validly signed file when the client first requests it to check the signature, and then a malicious one when the client loads the DLL.

The PoC can be found here: [https://github.com/exploits-forsale/themebleed](https://github.com/exploits-forsale/themebleed)

## Environment Prep

To run the PoC you will need two machines, one attacker machine which will run the SMB server, and one target machine where you will load the `.theme` file. Below are the requirements for the respective machines:

### Attacker machine

- Windows 10 or 11
- Disable "Server" service to free up the SMB port (disable and restart, do not just stop the service)
- Up to date .NET
- Accessible to target machine on the network

### Target machine

- Latest Windows 11

## Repro Steps

1. Create the `.theme` file by running: `themebleed.exe make_theme <attacker machine ip> exploit.theme`
2.  On the attacker machine run: `themebleed.exe server`
3. On the target machine open `exploit.theme`

This should result in the calculator opening on the target machine. This shows that arbitrary code has been executed.

## Credits

The PoC makes use of the [SMBLibrary](https://github.com/TalAloni/SMBLibrary) by Tal Aloni

## Conclusion

This is a reliable vulnerability that goes from loading a theme to downloading and executing code without memory corruption. Additionally this vulnerability appears to be new and only present in Windows 11. I would request that this submission be considered for bounty.

To fix this vulnerability I would recommend:

- Removing the "version 999" functionality altogether, but I'm not entirely sure what it's intended use is.
- Signing and verifying the `_vrf.dll` binary in the standard way Windows verifies other code, rather than this which is vulnerable to these kinds of race conditions.
- Disallow loading resources from remote shares in theme files.
- Add Mark-of-the-Web warnings to `.themepack` files.

> End of original report

## Reporting Timeline

- 5/15/2023 - Report and PoC submitted to Microsoft.
- 5/16/2023 - Acknowledgement of vulnerability by Microsoft.
- 5/17/2023 - $5,000 bounty rewarded
- 9/12/2023 - Fix released.

## Microsoft Fix Analysis

Microsoft's released fix for the issue removed the "version 999" functionality entirely. While that migitates this specific exploit, it still does not address the TOCTOU issue in the signing of `.msstyles` files.

Additionally Microsoft has not added Mark-of-the-Web warnings on `.themepack` files.

<small>

**extra thnx**

lander brandt - wellness director</br>
squiffy - transportation coordinator</br>
doomy - cultural attache</br>
ian - covid response</br>
james willy - support (emotional/financial/millitary)
