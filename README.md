# whatlicense
Full tool chain to extract WinLicense secrets from a protected program then launch it bypassing all verification steps, utlizing an Intel PIN tool and license file builder.

For a full technical breakdown of everything these tools are doing under the hood, see [tech_details.pdf](tech_details.pdf)

I have no qualms about releasing this because you still need the launcher for the final run, so this can't be used to make restributable cracked binaries.  This is helpful for older programs where the manufacturer is no longer around to ask for a license file from, as the verification mechanism seems to have remained unchanged for at least a decade.  It's also an academic curiosity, as the protection scheme is extraordinarily convoluted, involving multiple layers of decryption that are buried in virtualization.

I've tried to test this on programs protected with as many different versions of WL as possible, using the default virtualization engine and license scheme (ie. programs that use *regkey.dat* files, not the *SmartLicense* or registry key schemes, but these are the defaults you are going to run into the vast majority of the time.  It's difficult to find older versions of their protector software, so if you're running into problems, or find demos of some of their older versions, or can refer me to more products that employ it commercially, let me know so I can generalize this as much as possible.

Neither I nor this project are in any way endorsed or affiliated with Oreans WinLicense or Intel PIN.  No source code was ever seen and all tools were built solely through reverse engineering, so there is no copyrighted content contained in anywhere.

The license file building tool **wl-lic** includes [libtommath](https://github.com/libtom/libtommath), which was declared restriction-free (Unlicense) at the time of publication, and I place no further restrictions on your ability to re-use, resdistribute, modify, etc. any part of this project.  I don't make any warranties about any of it though, so I wouldn't drop any of it into anything mission-critical without thorough testing.

# building

Add the whatlicense root directory to your Intel PIN tools directory (eg. C:\pin\source\tools\whatlicense), open **whatlicense.sln** with Visual Studio and build as an "x86 Release" (this should be the only available option.)  A **/bin** directory will be created that contains the built executables.

If you run into issues with it, make sure you are building it from within your PIN tools directory, and if you really have trouble, **wl-lic** is just a *C++ Console* project, and you can build **wl-extract** by just a gutting a copy of **MyPinTool** that comes with PIN and replacing its code with that of **wl-extract**.

# usage

The overall process is to first build a dummy license file, which is internally consistent (correct layout and checksums), but is built with arbitrary keys that aren't valid for the protected program.  This is accomplished by running **wl-lic**:

```
wl-lic -d regkey.dat -r regkey.rsa
```

This will produce *regkey.dat*, which is our dummy license file, and *regkey.rsa*, which contains information about the associated RSA public keys needed to decrypt and verify it.

Next **wl-extract** is launched via PIN, supplying the files we just generated and the path to the protected program.  You can use **-o** to specify the log file, and if you already know the hardware ID (**HWID**) that WL generates for you, you can use the **-s** option to avoid searching for it in error messages, which is a lot faster since it can kill the program as soon as it extracts everything else.  You're **HWID** will look similar to *0123-4567-89AB-CDEF-FEDC-BA98-7654-3210*. It will usually be given to you during nag messages while trying to run the program without a license, or wherever you normally go to try to register it, since the developer would need it to build a license for you.

```
C:\pin\pin.exe -t wl-extract.dll -d regkey.dat -r regkey.rsa -o logfile -s -- C:\[path]\protected.exe
```

This will launch the protected program and start working through the verification steps, bypassing them and extracting and calculating the correct values.  You can monitor the logfile during this process for reasonably verbose progress updates.  When it is finished, it should generate a **main_hash** string near the end of the log.  It will be a long alpha-numeric string starting with *aaaa...*

We can now build a new license using your extracted **main_hash** and **HWID**, which will produce a license file built with all of the correct keys except for the RSA keys, which there is currently no way to overcome:

```
wl-lic -h HWID -m main_hash -d regkey2.dat -r regkey2.rsa
```

Finally, this license file can be used to launch the original program using the **-l** (lowercase L) option:

```
C:\pin\pin.exe -t wl-extract.dll -d regkey2.dat -r regkey2.rsa -o logfile -l -- C:\[path]\protected.exe
```

And it should open right up at that point. The launcher bypasses RSA, but skips the rest of the previous extraction steps then lets the program run normally from that point forward.  Since the license is otherwise built using all of the correct keys now, verification should pass and the program should launch.

# known issues

I haven't figured out how to fully detach the launcher after the RSA bypass just yet.  PIN_Detach() launches an external process that connects as a debugger in order to fully extricate the PIN framework and trips the anti-debug protections.  It's not as simple as just implementing ScyllaHide's techniques, because the PEB needs fixed after PIN's external process attaches, after we lose instrumentation ability.  We'll have to write some permanent patches that can catch and deal with it.

All instrumentation is removed after the RSA bypass, which lets the program run reasonably fast, but it's still running in JIT mode instead of natively, which isn't ideal.

More ideally would be to permanently patch the RSA public keys in the executable, so the launcher isn't required at all, but that'll require an equally monumental undertaking to this one, with the need to understand all of the unpacking and integrity check routines.

While the entire build process has been generalized as much as possible, there are slight differences between programs protected with different versions and even between programs protected by commercial and demo versions.  There is no official list of programs protected with it and older versions of even the demo protection software is difficult to track down, so it is difficult to thoroughly test this and it may not work on all protected programs.  If it's not working on something, refer me to it so I can see what's going on.

Some of the hash and key values that the license files implement never seemed to be verified at all during testing, and valid licenses could be built with completely arbitrary values for them even against commercially available products.  They may have put them in and then just never bothered to implement verifying them.  There's a haphazardness to the license format that would lead me to not at all be surprised by that, but it's disconcerting since there could be version out there that do verify these and I have no way to know how they work yet.

As before, don't pirate things.  You're going to have to use the launcher every time you run it and then it'll have to run in JIT mode the whole time.  It should get you in and give you the chance to properly evaluate the full version of something, but if you want the best experience, you're going to have to pay for it.
