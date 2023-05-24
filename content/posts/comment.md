+++
title = "Commenting can be tricky - Easy"
date = 2023-05-17
+++

Here we look at a screen drawing program.

## The Restriction

When we open up the app for the first time, we are greeted with the following window asking for our license:

![restriction_message](/drawing_restriction.png)

## Initial Investigation

Again, searching for references to the strings in this window brings us to the method `NMLicenseController::checkLicense` (converted to Objective-C from ghidra):

```Objective-C
char NMLicenseController::checkLicense(ID self,SEL param_2)

{
  ...
      else {
        [self setTitleWithMnemonic:@"Please purchase and input a license key..."];
        [self setEnableLicenseKeyInput:1];
        [self setCanContinue:0];

        uVar4 = [self nextButton];
        [uVar4 setTitle:@"Register"];
      }
  ...
}
```

## How to Return 1

It's reasonable to assume that a method named `checkLicense` that returns a `char` will return 1 (true) if the user has a valid license or 0 (false) otherwise.

Reviewing the beginning of this method seems to confirm this:

```Objective-C
char NMLicenseController::checkLicense(ID self,SEL param_2)
{
  NSLog(@"Check License");

  puVar9 = __got::_objc_msgSend;
  uVar4 = [NSBundle mainBundle];
  uVar5 = [uVar4 pathForResource:@"user" ofType:@"dat"];

  uVar4 = [NSFileManager defaultManager];
  cVar1 = [uVar4 fileExistsAtPath:uVar5];

  if (cVar1 != '\0') {
    uVar4 = [NSString stringWithContentsOfFile:uVar5 encoding:0x1 error:0x0];
    lVar6 = [uVar4 rangeOfString:@"//"];

    if (lVar6 != 0) {
      NSLog(@"Licensed to %@!", uVar4);

      [self setIsTrial:0];
      [self setUserName:uVar4];

      cVar1 = '\x01';
      goto exit;
    }
  }
  ...
}
```

The method first checks if the file `<app path/Contents/Resources/user.dat` exists.

Then, if the contents of that file does not start with "//" then we are licensed and ready to go!

## Unlocking

All we need to do now is create the "user.dat" file and the software thinks we have a valid license!

We just need to make sure that the username is not commented out!
