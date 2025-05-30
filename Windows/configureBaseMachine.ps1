#---------------------------------------------------------------------------------------------------------------------------------------------
#
# 1. Use this script to configure a base system. 
# 2. Export the xml to create a domain policy. 
#
# Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/customize-exploit-protection 
#
#---------------------------------------------------------------------------------------------------------------------------------------------



#---------------------------------------------------------------------------------------------------------------------------------------------
# PER-PROCESS Configurations
#
# Syntax and Example:
# Set-ProcessMitigation -<scope> <app executable> -<action> <mitigation or options>,<mitigation or options>,<mitigation or options>
# Set-ProcessMitigation -Name c:\apps\lob\tests\testing.exe -Enable DEP, EmulateAtlThunks, DisallowChildProcessCreation

Set-ProcessMitigation -Name acrobat.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess,BlockLowLabelImageLoads, BlockRemoteImageLoads, DisableNonSystemFonts, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, ForceRelocateImages, RequireInfo, StrictHandle, UserShadowStack  
Set-ProcessMitigation -Name AcroRd32.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name AppControlManager.exe -Enable BlockLowLabelImageLoads, BlockRemoteImageLoads, DisableNonSystemFonts, EnableExportAddressFilter, EnableExportAddressFilterPlus, EnableImportAddressFilter, EnableRopCallerCheck, EnableRopStackPivot, UserShadowStack, UserShadowStackStrictMode  
Set-ProcessMitigation -Name chrome.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,SEHOP,AuditChildProcess
Set-ProcessMitigation -Name csrss.exe -Enable BlockRemoteImageLoads 
Set-ProcessMitigation -Name excel.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess,AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle  
Set-ProcessMitigation -Name explorer.exe -Enable DisableExtensionPoints, StrictHandle  
Set-ProcessMitigation -Name firefox.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name fltldr.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name groove.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,BlockRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,DisallowChildProcessCreation
Set-ProcessMitigation -Name iexplore.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name infopath.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name java.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name javaw.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name javaws.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name lsass.exe -Enable BlockDynamicCode, BlockRemoteImageLoads, DisableExtensionPoints, DisallowChildProcessCreation, MicrosoftSignedOnly  
Set-ProcessMitigation -Name lync.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name msaccess.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess, AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle
Set-ProcessMitigation -Name msedge.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess, AllowStoreSignedBinaries, BlockLowLabelImageLoads, BlockRemoteImageLoads, CFG, DisableExtensionPoints, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictCFG, UserShadowStack, UserShadowStackStrictMode  
Set-ProcessMitigation -Name msedgewebview2.exe -Enable CFG, DisableExtensionPoints, EnforceModuleDependencySigning, StrictCFG
Set-ProcessMitigation -Name mspub.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess,AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle
Set-ProcessMitigation -Name NisSrv.exe -Enable MicrosoftSignedOnly
Set-ProcessMitigation -Name onedrive.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess,AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle  
Set-ProcessMitigation -Name onenote.exe -Enable AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle  
Set-ProcessMitigation -Name outlook.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess, AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle
Set-ProcessMitigation -Name plugin-container.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name powerpnt.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess, AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle  
Set-ProcessMitigation -Name pptview.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name QuickAssist.exe -Enable AllowStoreSignedBinaries, BlockDynamicCode, BlockLowLabelImageLoads, BlockRemoteImageLoads, DisableExtensionPoints, DisableNonSystemFonts, EnableExportAddressFilter, EnableExportAddressFilterPlus, EnableImportAddressFilter, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle, UserShadowStack, UserShadowStackStrictMode  
Set-ProcessMitigation -Name quip.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,SEHOP,AuditChildProcess
Set-ProcessMitigation -Name Regsvr32.exe -Enable BlockLowLabelImageLoads  
Set-ProcessMitigation -Name rundll32.exe -Enable BlockLowLabelImageLoads, BlockRemoteImageLoads  
Set-ProcessMitigation -Name RuntimeBroker.exe -Enable CFG, DisableExtensionPoints, EnforceModuleDependencySigning, StrictCFG
Set-ProcessMitigation -Name services.exe -Enable BlockRemoteImageLoads  
Set-ProcessMitigation -Name slack.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,SEHOP,AuditChildProcess
Set-ProcessMitigation -Name SmartScreen.exe -Enable CFG, DisableExtensionPoints, MicrosoftSignedOnly, StrictCFG  
Set-ProcessMitigation -Name SMSS.exe -Enable BlockRemoteImageLoads  
Set-ProcessMitigation -Name visio.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name WindowsSandbox.exe -Enable BlockLowLabelImageLoads, BlockRemoteImageLoads, CFG, DisableExtensionPoints, EnableExportAddressFilter, EnableExportAddressFilterPlus, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictCFG, StrictHandle  
Set-ProcessMitigation -Name WindowsSandboxClient.exe -Enable BlockLowLabelImageLoads, BlockRemoteImageLoads, CFG, DisableExtensionPoints, EnableExportAddressFilter, EnableExportAddressFilterPlus, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictCFG, StrictHandle  
Set-ProcessMitigation -Name Wininit.exe -Enable BlockRemoteImageLoads  
Set-ProcessMitigation -Name winword.exe -Enable DEP,BottomUp,ForceRelocateImages,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess, AllowStoreSignedBinaries, DisableExtensionPoints, EnableRopCallerCheck, EnableRopStackPivot, EnforceModuleDependencySigning, MicrosoftSignedOnly, StrictHandle 
Set-ProcessMitigation -Name wmplayer.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name wordpad.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,EnableExportAddressFilter,EnableExportAddressFilterPlus,EnableImportAddressFilter,EnableRopStackPivot,EnableRopCallerCheck,EnableRopSimExec,SEHOP,TerminateOnError,AuditChildProcess
Set-ProcessMitigation -Name vmcompute.exe -Enable CFG, StrictCFG
Set-ProcessMitigation -Name vmwp.exe -Enable CFG, StrictCFG  
Set-ProcessMitigation -Name zoom.exe -Enable DEP,BottomUp,CFG,AuditRemoteImageLoads,AuditLowLabelImageLoads,SEHOP,AuditChildProcess

#---------------------------------------------------------------------------------------------------------------------------------------------



#---------------------------------------------------------------------------------------------------------------------------------------------
# SYSTEM WIDE Configurations
#
# Example:
# Set-Processmitigation -System -Enable DEP
# Note, the options must be specified in a single command or they will overide current config.

Set-ProcessMitigation -System -Enable DEP,BottomUp,CFG,SEHOP  
# Set-ProcessMitigation -System -Enable DEP,BottomUp,SEHOP// We re-enabled CFG as default 10/21/19.

#---------------------------------------------------------------------------------------------------------------------------------------------



#---------------------------------------------------------------------------------------------------------------------------------------------
#
# Clear a setting:
# Set-Processmitigation -Name test.exe -Remove -Disable DEP

#---------------------------------------------------------------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------------------------------------------------------------
#
# Export Settings for Deployment:
Get-ProcessMitigation -RegistryConfigFilePath settings.xml 

#---------------------------------------------------------------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------------------------------------------------------------
#
# Import Settings on a test or base machine
#Set-ProcessMitigation -PolicyFilePath settings.xml 

#---------------------------------------------------------------------------------------------------------------------------------------------
