# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Describe 'Registry offline hive tests' -Skip:(!$IsWindows) {
    BeforeAll {
        $testHivesSource = Join-Path $PSScriptRoot 'test_hives'

        # Applies a deterministic, machine-independent descriptor to a file:
        # inheritance blocked, exactly one explicit ACE for BUILTIN\Administrators.
        # Deliberately not the current user - CI agents differ.
        function Set-MarkerAcl {
            param([string]$Path)
            $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)   # protect, drop inherited
            $acl.AddAccessRule(
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $admins, 'FullControl', 'Allow'))
            Set-Acl -LiteralPath $Path -AclObject $acl
        }

        function Get-AclSummary {
            param([string]$Path)
            $acl = Get-Acl -LiteralPath $Path
            [pscustomobject]@{
                Protected = $acl.AreAccessRulesProtected
                AceCount  = @($acl.Access).Count
                Sids      = @($acl.Access | ForEach-Object {
                                $_.IdentityReference.Translate(
                                    [System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object)
                Owner     = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            }
        }
    }

    Context 'Get from offline HKLM hive' {
        BeforeAll {
            $script:hklmHive = Join-Path $TestDrive 'HKLM.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hklmHive
        }

        It 'Can get a registry key from offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $out = registry config get --input $json 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
        }

        It 'Can get a string value from offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestString'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $out = registry config get --input $json 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
            $result.valueName | Should -Be 'TestString'
            $result.valueData.String | Should -Be 'TestValue'
        }

        It 'Can get a DWORD value from offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestDword'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $out = registry config get --input $json 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
            $result.valueName | Should -Be 'TestDword'
            $result.valueData.DWord | Should -Be 42
        }

        It 'Returns _exist false for non-existent key in offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\NonExistent'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $out = registry config get --input $json 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result._exist | Should -Be $false
        }

        It 'Returns _exist false for non-existent value in offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'DoesNotExist'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $out = registry config get --input $json 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result._exist | Should -Be $false
        }
    }

    Context 'Get from offline HKCU hive' {
        BeforeAll {
            $script:hkcuHive = Join-Path $TestDrive 'HKCU.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKCU.hiv') -Destination $script:hkcuHive
        }

        It 'Can get a string value from offline HKCU hive' {
            $json = @{
                keyPath = 'HKCU\Software\DSCUserTest'
                valueName = 'UserString'
                registryFilePath = $script:hkcuHive
            } | ConvertTo-Json -Compress
            $out = registry config get --input $json 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result.keyPath | Should -Be 'HKCU\Software\DSCUserTest'
            $result.valueName | Should -Be 'UserString'
            $result.valueData.String | Should -Be 'UserValue'
        }
    }

    Context 'Set in offline hive' {
        BeforeEach {
            $script:hklmHive = Join-Path $TestDrive 'HKLM_set.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hklmHive
        }

        It 'Can set a new value in offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'NewValue'
                valueData = @{ String = 'Hello' }
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress -Depth 3
            $out = registry config set --input $json 2>$null
            $LASTEXITCODE | Should -Be 0

            # Verify the value was written
            $getJson = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'NewValue'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config get --input $getJson 2>$null | ConvertFrom-Json
            $result.valueData.String | Should -Be 'Hello'
        }

        It 'Can create a new key in offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\NewKey\SubKey'
                valueName = 'Test'
                valueData = @{ DWord = 99 }
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress -Depth 3
            $null = registry config set --input $json 2>$null
            $LASTEXITCODE | Should -Be 0

            # Verify
            $getJson = @{
                keyPath = 'HKLM\Software\NewKey\SubKey'
                valueName = 'Test'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config get --input $getJson 2>$null | ConvertFrom-Json
            $result.valueData.DWord | Should -Be 99
        }
    }

    Context 'Delete from offline hive' {
        BeforeEach {
            $script:hklmHive = Join-Path $TestDrive 'HKLM_delete.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hklmHive
        }

        It 'Can delete a value from offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestString'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $null = registry config delete --input $json 2>$null
            $LASTEXITCODE | Should -Be 0

            # Verify value is gone
            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $result._exist | Should -Be $false
        }

        It 'Can delete a key from offline hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $null = registry config delete --input $json 2>$null
            $LASTEXITCODE | Should -Be 0

            # Verify key is gone
            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $result._exist | Should -Be $false
        }
    }

    Context 'RegistryList with offline hive' {
        BeforeAll {
            $script:hklmHive = Join-Path $TestDrive 'HKLM_list.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hklmHive
        }

        It 'Can get multiple values from offline hive using RegistryList' {
            $listJson = @{
                registryFilePath = $script:hklmHive
                registryEntries = @(
                    @{ keyPath = 'HKLM\Software\DSCTest'; valueName = 'TestString' }
                    @{ keyPath = 'HKLM\Software\DSCTest'; valueName = 'TestDword' }
                    @{ keyPath = 'HKLM\Software\DSCTest'; valueName = 'NonExistent' }
                )
            } | ConvertTo-Json -Compress -Depth 3
            $out = registry config get --list --input $listJson 2>$null
            $LASTEXITCODE | Should -Be 0
            $result = $out | ConvertFrom-Json
            $result.registryEntries.Count | Should -Be 3
            $result.registryEntries[0].valueData.String | Should -Be 'TestValue'
            $result.registryEntries[1].valueData.DWord | Should -Be 42
            $result.registryEntries[2]._exist | Should -BeFalse
        }

        It 'Can get multiple values from offline hive using dsc config get' {
            $config_yaml = @"
`$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
- name: Reg List
  type: Microsoft.Windows/RegistryList
  properties:
    registryFilePath: '$($script:hklmHive -replace '\\', '\\')'
    registryEntries:
    - keyPath: HKLM\Software\DSCTest
      valueName: TestString
    - keyPath: HKLM\Software\DSCTest
      valueName: TestDword
    - keyPath: HKLM\Software\DSCTest
      valueName: NonExistent
"@
            $out = dsc config get --input $config_yaml 2>$TestDrive/error.log | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0 -Because (Get-Content -Raw $TestDrive/error.log)
            $out.results.result[0].actualState.registryEntries.Count | Should -Be 3
            $out.results.result[0].actualState.registryEntries[0].valueData.String | Should -Be 'TestValue'
            $out.results.result[0].actualState.registryEntries[1].valueData.DWord | Should -Be 42
            $out.results.result[0].actualState.registryEntries[2]._exist | Should -BeFalse
        }
    }

    Context 'What-if set in offline hive' {
        BeforeEach {
            $script:hklmHive = Join-Path $TestDrive 'HKLM_whatif.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hklmHive
        }

        It 'What-if set reports keys to create without modifying hive' {
            $json = @{
                keyPath = 'HKLM\Software\NewKey\SubKey'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config set -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.keyPath | Should -Be 'HKLM\Software\NewKey\SubKey'
            $result._metadata.whatIf | Should -Not -BeNullOrEmpty

            # Verify hive was NOT modified
            $getResult = registry config get --input $json 2>$null | ConvertFrom-Json
            $getResult._exist | Should -Be $false
        }

        It 'What-if set reports value to create without modifying hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'WhatIfValue'
                valueData = @{ String = 'ShouldNotExist' }
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress -Depth 3
            $result = registry config set -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.valueName | Should -Be 'WhatIfValue'
            $result.valueData.String | Should -Be 'ShouldNotExist'

            # Verify hive was NOT modified
            $getJson = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'WhatIfValue'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $getResult = registry config get --input $getJson 2>$null | ConvertFrom-Json
            $getResult._exist | Should -Be $false
        }

        It 'What-if set on existing value reports no changes' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestString'
                valueData = @{ String = 'TestValue' }
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress -Depth 3
            $result = registry config set -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
            $result.valueName | Should -Be 'TestString'
            # No whatIf metadata means no changes needed
            ($result.psobject.properties | Where-Object { $_.Name -eq '_metadata' } | Measure-Object).Count | Should -Be 0
        }
    }

    Context 'What-if delete in offline hive' {
        BeforeEach {
            $script:hklmHive = Join-Path $TestDrive 'HKLM_whatif_del.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hklmHive
        }

        It 'What-if delete value reports deletion without modifying hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestString'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config delete -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
            $result._metadata.whatIf | Should -Match 'TestString'

            # Verify hive was NOT modified - value still readable
            $getResult = registry config get --input $json 2>$null | ConvertFrom-Json
            $getResult._exist | Should -Not -Be $false
            $getResult.valueData.String | Should -Be 'TestValue'
        }

        It 'What-if delete key reports deletion without modifying hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config delete -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
            $result._metadata.whatIf | Should -Match 'DSCTest'

            # Verify hive was NOT modified - key still exists
            $getResult = registry config get --input $json 2>$null | ConvertFrom-Json
            $getResult._exist | Should -Not -Be $false
            $getResult.keyPath | Should -Be 'HKLM\Software\DSCTest'
        }

        It 'What-if delete non-existent value is a no-op' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'DoesNotExist'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config delete -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result._exist | Should -Be $false
        }

        It 'What-if set with _exist false reports value deletion without modifying hive' {
            $json = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestString'
                _exist = $false
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $result = registry config set -w --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.keyPath | Should -Be 'HKLM\Software\DSCTest'
            $result._metadata.whatIf | Should -Match 'TestString'

            # Verify hive was NOT modified
            $getJson = @{
                keyPath = 'HKLM\Software\DSCTest'
                valueName = 'TestString'
                registryFilePath = $script:hklmHive
            } | ConvertTo-Json -Compress
            $getResult = registry config get --input $getJson 2>$null | ConvertFrom-Json
            $getResult._exist | Should -Not -Be $false
            $getResult.valueData.String | Should -Be 'TestValue'
        }
    }

    <#
        Regression tests for two offline-registry defects:

          Issue 1 - `get` does not return `registryFilePath`, so the synthetic test never
                    converges and offline operations are never idempotent.
          Issue 2 - `OfflineHive::save` deletes the target file before calling ORSaveHive,
                    discarding the file's DACL, inheritance-protection flag and owner.

        None of these require elevation, except where noted.

        Each test is tagged in a comment as:
          [FAILS TODAY]  - currently red; turns green when the defect is fixed.
          [GUARD]        - currently green; present to stop a fix or future change
                           regressing behaviour that works now.

        Deliberately not asserted:

          * Creation time. ReplaceFile preserves it, but so does NTFS file-system
            tunnelling, which restores the creation time of a file deleted and recreated
            under the same name within roughly 15 seconds. The current delete-and-rewrite
            implementation would therefore pass a creation-time assertion for the wrong
            reason, making it useless as a regression test.
          * File ID / index number. ReplaceFile documents that the resulting file takes the
            file ID of the *replacement*, so this legitimately changes under the suggested
            fix and must not be asserted as stable.
    #>

    # ---------------------------------------------------------------------------
    # Issue 1 - registryFilePath must round-trip so the synthetic test can converge
    # ---------------------------------------------------------------------------

    Context 'Issue 1 - registryFilePath round-trips through get' {

        BeforeEach {
            $script:hive = Join-Path $TestDrive 'HKLM_roundtrip.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hive -Force
        }

        # [FAILS TODAY] The core assertion. Everything else in Issue 1 follows from this.
        It 'Returns registryFilePath for an existing value' {
            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'TestString'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.registryFilePath | Should -Be $script:hive
        }

        # [FAILS TODAY] get_offline has four return sites. The two "not found" paths are
        # the easy ones to miss when applying the fix, so cover them explicitly.
        It 'Returns registryFilePath when the key does not exist' {
            $json = @{
                keyPath          = 'HKLM\Software\NoSuchKey'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $result._exist          | Should -BeFalse
            $result.registryFilePath | Should -Be $script:hive
        }

        # [FAILS TODAY]
        It 'Returns registryFilePath when the value does not exist' {
            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'NoSuchValue'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $result._exist          | Should -BeFalse
            $result.registryFilePath | Should -Be $script:hive
        }

        # [FAILS TODAY]
        It 'Returns registryFilePath for a key-only get' {
            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $result.registryFilePath | Should -Be $script:hive
        }

        # [GUARD] The fix must not start emitting the property on the live path - that
        # would break idempotency for every existing live-registry instance.
        It 'Omits registryFilePath when operating on the live registry' {
            $json = @{ keyPath = 'HKCU\Software' } | ConvertTo-Json -Compress

            $result = registry config get --input $json 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.PSObject.Properties.Name | Should -Not -Contain 'registryFilePath'
        }
    }

    Context 'Issue 1 - offline instances converge' {

        BeforeEach {
            $script:hive = Join-Path $TestDrive 'HKLM_converge.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hive -Force
            $script:instance = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'ConvergeMe'
                valueData        = @{ DWord = 7 }
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress -Depth 3
        }

        # [FAILS TODAY] The user-visible symptom. Kept separate from the get test above:
        # a fix that satisfies one without the other (for example by suppressing the
        # property from comparison rather than returning it) should still be caught.
        It 'Reports inDesiredState after a successful set' {
            dsc resource set -r Microsoft.Windows/Registry --input $script:instance 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            $test = dsc resource test -r Microsoft.Windows/Registry --input $script:instance 2>$null |
                ConvertFrom-Json
            $test.inDesiredState      | Should -BeTrue
            $test.differingProperties | Should -BeNullOrEmpty
        }

        # [FAILS TODAY] The concrete harm. Microsoft.Windows/Registry does not declare
        # set.implementsPretest, so DSC tests first and skips set entirely when the
        # instance is already in the desired state. A converged instance must therefore
        # leave the hive file completely untouched on a second run.
        It 'Does not rewrite the hive file on a redundant set' {
            dsc resource set -r Microsoft.Windows/Registry --input $script:instance 2>$null | Out-Null
            $stamp = (Get-Item -LiteralPath $script:hive).LastWriteTimeUtc
            $bytes = (Get-Item -LiteralPath $script:hive).Length

            Start-Sleep -Milliseconds 1100   # ensure a rewrite would be observable

            dsc resource set -r Microsoft.Windows/Registry --input $script:instance 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            (Get-Item -LiteralPath $script:hive).LastWriteTimeUtc | Should -Be $stamp
            (Get-Item -LiteralPath $script:hive).Length           | Should -Be $bytes
        }

        # [FAILS TODAY] what-if on an already-converged instance should report nothing to do.
        It 'Reports no changes for what-if on a converged instance' {
            dsc resource set -r Microsoft.Windows/Registry --input $script:instance 2>$null | Out-Null

            $whatIf = dsc resource set -w -r Microsoft.Windows/Registry --input $script:instance 2>$null |
                ConvertFrom-Json
            $whatIf.changedProperties | Should -BeNullOrEmpty
        }
    }

    Context 'Issue 1 - RegistryList' {

        BeforeEach {
            $script:hive = Join-Path $TestDrive 'HKLM_listconverge.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hive -Force
            $script:list = @{
                registryFilePath = $script:hive
                registryEntries  = @(
                    @{ keyPath = 'HKLM\Software\DSCTest'; valueName = 'L1'; valueData = @{ DWord = 1 } }
                    @{ keyPath = 'HKLM\Software\DSCTest'; valueName = 'L2'; valueData = @{ String = 'two' } }
                )
            } | ConvertTo-Json -Compress -Depth 5
        }

        # [FAILS TODAY] The list-level property is propagated to each entry, so it has to
        # round-trip at the list level too.
        It 'Returns the list-level registryFilePath from get' {
            $result = registry config get --list --input $script:list 2>$null | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.registryFilePath | Should -Be $script:hive
        }

        # [FAILS TODAY]
        It 'Reports inDesiredState after a successful list set' {
            dsc resource set -r Microsoft.Windows/RegistryList --input $script:list 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            $test = dsc resource test -r Microsoft.Windows/RegistryList --input $script:list 2>$null |
                ConvertFrom-Json
            $test.inDesiredState      | Should -BeTrue
            $test.differingProperties | Should -BeNullOrEmpty
        }
    }

    # ---------------------------------------------------------------------------
    # Issue 2 - saving must not disturb the hive file's security descriptor
    # ---------------------------------------------------------------------------

    Context 'Issue 2 - security descriptor is preserved across save' {

        BeforeEach {
            $script:hive = Join-Path $TestDrive 'HKLM_acl.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hive -Force
            Set-MarkerAcl -Path $script:hive
            $script:before = Get-AclSummary -Path $script:hive
        }

        # [FAILS TODAY] Today: Protected goes True -> False and the explicit ACE is
        # replaced by whatever the containing directory hands down.
        It 'Preserves the DACL and inheritance-protection flag across set' {
            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'AclProbe'
                valueData        = @{ DWord = 1 }
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress -Depth 3

            registry config set --input $json 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            $after = Get-AclSummary -Path $script:hive
            $after.Protected | Should -BeTrue
            $after.AceCount  | Should -Be $script:before.AceCount
            $after.Sids      | Should -Be $script:before.Sids
        }

        # [FAILS TODAY] remove_offline has two separate save call sites (value delete and
        # key delete). Cover both so a fix applied to only one is caught.
        It 'Preserves the DACL across value delete' {
            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'TestString'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            registry config delete --input $json 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            $after = Get-AclSummary -Path $script:hive
            $after.Protected | Should -BeTrue
            $after.Sids      | Should -Be $script:before.Sids
        }

        # [FAILS TODAY]
        It 'Preserves the DACL across key delete' {
            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            registry config delete --input $json 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            $after = Get-AclSummary -Path $script:hive
            $after.Protected | Should -BeTrue
            $after.Sids      | Should -Be $script:before.Sids
        }

        # [INCONCLUSIVE WITHOUT SETUP] ReplaceFile does not preserve the owner, so a fix
        # based on it needs to restore the owner explicitly. This only exercises the defect
        # when the hive's owner differs from the identity running the test - otherwise a
        # recreated file gets the same owner and the assertion passes for the wrong reason.
        # Setting a foreign owner needs SeRestorePrivilege, hence the elevation gate.
        It 'Preserves the file owner across set' -Skip:(-not ([System.Security.Principal.WindowsPrincipal]::new(
                [System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
                [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            # Give the file an owner that is not the writing process.
            $acl = Get-Acl -LiteralPath $script:hive
            $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))  # SYSTEM
            Set-Acl -LiteralPath $script:hive -AclObject $acl
            $script:before = Get-AclSummary -Path $script:hive
            $script:before.Owner | Should -Be 'S-1-5-18'

            $json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'OwnerProbe'
                valueData        = @{ DWord = 1 }
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress -Depth 3

            registry config set --input $json 2>$null | Out-Null
            (Get-AclSummary -Path $script:hive).Owner | Should -Be $script:before.Owner
        }
    }

    Context 'Issue 2 - save is safe and leaves no debris' {

        BeforeEach {
            $script:dir  = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $script:dir | Out-Null
            $script:hive = Join-Path $script:dir 'HKLM_safe.hiv'
            Copy-Item (Join-Path $testHivesSource 'HKLM.hiv') -Destination $script:hive -Force
            $script:json = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'SafeProbe'
                valueData        = @{ DWord = 1 }
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress -Depth 3
        }

        # [GUARD] A ReplaceFile-based fix writes a temporary file and optionally a backup.
        # Neither may survive a successful save.
        It 'Leaves no temporary or backup files after a successful set' {
            registry config set --input $script:json 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            @(Get-ChildItem -LiteralPath $script:dir -Force).Name | Should -Be @('HKLM_safe.hiv')
        }

        # [GUARD] Currently passes because remove_file fails before anything is destroyed.
        # The point is to keep it passing: a ReplaceFile-based fix must pass a backup file
        # name, otherwise the documented ERROR_UNABLE_TO_MOVE_REPLACEMENT path leaves the
        # target deleted - the same exposure this issue is about.
        It 'Leaves the hive intact when the save cannot complete' {
            $original = (Get-FileHash -LiteralPath $script:hive -Algorithm SHA256).Hash

            # Deny delete and write to other processes while permitting the read that
            # OROpenHive needs.
            $lock = [System.IO.File]::Open(
                $script:hive,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read)
            try {
                registry config set --input $script:json 2>$null | Out-Null
                $LASTEXITCODE | Should -Not -Be 0
            }
            finally {
                $lock.Dispose()
            }

            Test-Path -LiteralPath $script:hive | Should -BeTrue
            (Get-FileHash -LiteralPath $script:hive -Algorithm SHA256).Hash | Should -Be $original
        }

        # [GUARD] Any change to how the hive is written must keep unrelated content intact.
        It 'Preserves unrelated existing values across a save' {
            registry config set --input $script:json 2>$null | Out-Null
            $LASTEXITCODE | Should -Be 0

            $check = @{
                keyPath          = 'HKLM\Software\DSCTest'
                valueName        = 'TestString'
                registryFilePath = $script:hive
            } | ConvertTo-Json -Compress

            $result = registry config get --input $check 2>$null | ConvertFrom-Json
            $result.valueData.String | Should -Be 'TestValue'
        }
    }
}
