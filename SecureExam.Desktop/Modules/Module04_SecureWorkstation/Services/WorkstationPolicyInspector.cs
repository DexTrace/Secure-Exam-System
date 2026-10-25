using Microsoft.Win32;
using System.IO;
using System.Runtime.InteropServices;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal static class WorkstationPolicyInspector
{
    public static WorkstationPolicyReport Inspect()
    {
        var isWindows = OperatingSystem.IsWindows();
        if (!isWindows)
        {
            return new WorkstationPolicyReport
            {
                OperatingSystem = RuntimeInformation.OSDescription,
                Windows = false
            };
        }

        return new WorkstationPolicyReport
        {
            OperatingSystem = RuntimeInformation.OSDescription,
            Windows = true,
            ApplicationControlPolicyDetected = IsAppLockerEnforced() || HasWdacPolicy(),
            SystemRestrictionsConfigured = HasSystemRestrictions()
        };
    }

    private static bool IsAppLockerEnforced()
    {
        using var policy = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe");
        return policy?.GetValue("EnforcementMode") is int enforcementMode && enforcementMode == 1;
    }

    private static bool HasWdacPolicy()
    {
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var policyDirectory = Path.Combine(
            windowsDirectory,
            "System32",
            "CodeIntegrity",
            "CiPolicies",
            "Active");
        return Directory.Exists(policyDirectory) &&
                   Directory.EnumerateFiles(policyDirectory, "*.cip").Any() ||
               File.Exists(Path.Combine(windowsDirectory, "System32", "CodeIntegrity", "SIPolicy.p7b"));
    }

    private static bool HasSystemRestrictions()
    {
        using var machinePolicy = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Policies\Microsoft\Windows\System");
        using var userPolicy = Registry.CurrentUser.OpenSubKey(
            @"SOFTWARE\Policies\Microsoft\Windows\System");
        using var machineSecurityPolicy = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
        using var userSecurityPolicy = Registry.CurrentUser.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");

        return IsEnabled(machinePolicy, "DisableCMD") ||
               IsEnabled(userPolicy, "DisableCMD") ||
               IsEnabled(machineSecurityPolicy, "DisableTaskMgr") ||
               IsEnabled(userSecurityPolicy, "DisableTaskMgr");
    }

    private static bool IsEnabled(RegistryKey? key, string valueName) =>
        key?.GetValue(valueName) is int value && value == 1;
}
