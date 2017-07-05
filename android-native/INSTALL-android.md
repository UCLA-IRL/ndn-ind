NDN-CPP: A Named Data Networking client library for C++ and C - Android
=======================================================================

This are instructions to cross-compile NDN-CPP for Android.

Prerequisites
=============

* Required: Android Studio (version 2.2 or higher)
* Required: Android LLDB, CMake and NDK
* Required: OpenSSL 1.0.x.
* Required: perl (for configuring the OpenSSL build)

## macOS 10.12

Required: Install Android Studio from https://developer.android.com/studio/index.html .
(Tested with Android Studio 2.3.3 .)

Required: In the Android Studio SDK Manager, install LLDB, CMake and NDK following the instructions at
https://developer.android.com/ndk/guides/index.html

Set the environment variables ANDROID_SDK_ROOT and ANDROID_NDK_ROOT to the installed location, for example:

    export ANDROID_SDK_ROOT=~/Library/Android/sdk
    export ANDROID_NDK_ROOT=~/Library/Android/sdk/ndk-bundle

Required: Download the latest OpenSSL 1.0.x from https://www.openssl.org/source . Extract the files, for example:

    tar xvfz openssl-1.0.2l.tar.gz

Prepare OpenSSL
===============

(These instructions are taken from https://wiki.openssl.org/index.php/Android .)
Make sure the environment variables ANDROID_SDK_ROOT and ANDROID_NDK_ROOT are set (see above).
To run the OpenSSL setup script, in the following change <NDN-CPP-root> to the root of the NDN-CPP distribution. In
a terminal, enter:

    . <NDN-CPP-root>/android-native/setenv-android.sh

(This runs the script from https://wiki.openssl.org/images/7/70/Setenv-android.sh which is configured for
android-ndk-r9 and arm . You may need to edit it to change _ANDROID_NDK, _ANDROID_ARCH, _ANDROID_EABI
and _ANDROID_API . For details, see https://wiki.openssl.org/index.php/Android#Adjust_the_Cross-Compile_Script .)

In a terminal, change directory to the extracted openssl distribution and enter:

    perl -pi -e 's/install: all install_docs install_sw/install: install_docs install_sw/g' Makefile.org
    ./config shared no-asm no-ssl2 no-ssl3 no-comp no-hw no-engine --openssldir=.
    make depend

Build
=====

Create a new Android project with the following configuration:

* In the New Project wizard, name the project (e.g. "ndn-cpp-native"). Be sure to check "Include C++ support".
* Select a minimum SDK. This has been tested with "API 21: Android 5.0 (Lollipop)".
* Select the Basic Activity template.
* In the Customize C++ Support screen, for the C++ Standard, select "C++11". Check "Exceptions Support"
  and "Runtime Type Information Support".
* Click Finish to complete the New Project wizard.

Set up CMake as follows. In a terminal, change directory to the root of your Android Studio project,
for example "/Users/myusername/AndroidStudioProjects/ndn-cpp-native".

To make a link to NDN-CPP, in the following change <NDN-CPP-root> to the root of the NDN-CPP distribution:

    ln -s <NDN-CPP-root> app/src/ndn-cpp

To make a link to OpenSSL, in the following change <OpenSSL> to the extracted OpenSSL distribution:

    ln -s <OpenSSL> app/src/openssl

The Android config.h mainly selects the std shared_ptr and other defaults.
Copy it to the NDN-CPP include folder:

    cp app/src/ndn-cpp/android-native/ndn-cpp-config.h app/src/ndn-cpp/include/ndn-cpp

Replace the CMake file with the NDN-CPP version that makes libndn-cpp:

    cp app/src/ndn-cpp/android-native/CMakeLists.txt app

(In Android Studio, if it says "Unregistered VCS root detected", click ignore.)

in Android Studio, in the Build menu, click Rebuild Project. The libndn-cpp.so library file is in the
app/build/intermediates/cmake/debug/obj subfolder of your Android Studio project. For example if your
Android system is armeabi, then the library file is app/build/intermediates/cmake/debug/obj/armeabi/libndn-cpp.so .

## Unity on Android

To use libndn-cpp.so in your Unity on Android project, copy libndn-cpp.so to the
subfolder Assets/Plugins/Android of your Unity project folder. (Create this
folder if it doesn't exist.)