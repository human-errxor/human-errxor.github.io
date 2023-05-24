+++
title = "Pick a key, any key - Medium"
date = 2023-05-18
+++

In this post, we'll crack a moderately well-known application to help with practicing music.

Since this application, presumable makes more money, we'll find that the complexity of its protection is moderately more complex than the previous examples.

## The Restriction

As usual, there is a dialog to purchase a license after a second or two of using the app:

![restriction_message](/hashing_restriction.png)

## Initial Investigation

This time, ghidra does not pick detect any references to the strings in the dialog.

Instead, if we can search for strings in the binary like "trial", "register", or "license".

Searching for "activate" shows us a string "activated" with the following code referencing it (function label inferred):

```C
void check_if_product_activated(void)
{
    ...
    uVar8 = __stubs::_objc_allocWithZone(&_OBJC_CLASS_$_PADProduct);
    *(lVar13 + -8) = 0x1000e1abe;
    uVar5 = (*__got::_objc_retain)(uVar5);
    *(lVar13 + -8) = 0x1000e1ada;
    uVar9 = __stub_helper::thunk_FUN_1004a5ce0(0x323533393934,0xe600000000000000);
                    /* [undefined initWithProductID:undefined productType:0x0
                       configuration:<<unknown>>] */
    *(lVar13 + -8) = 0x1000e1af4;
    lVar11 = __stubs::_objc_msgSend
                       (uVar8,"initWithProductID:productType:configuration:",uVar9,0,uVar5);
    ...
                    /* [undefined activated] */
    *(lVar13 + -8) = 0x1000e1b1b;
    cVar3 = __stubs::_objc_msgSend(lVar11,"activated");
    if (cVar3 == '\0') {
      ...
    }
    else {
      ...
      __stubs::_objc_msgSend(uVar8,"verifyActivationWithCompletion:",pvVar12);
      ...
    }
  }
  return;
}
```

It looks like this is an Objective-C selector so let's rewrite it as Objective-C:

```Objective-C
void check_if_product_activated(void)
{
    ...
    lVar11 = [[PADProduct alloc] initWithProductID:uvar9
                                 productType:0
                                 configuration:uVar5];
    ...
    if (!lVar1.activated) {
      ...
    }
    else {
      ...
      [lVar11 verifyActivationWithCompletion:pvVar12];
      ...
    }
  }
  return;
}
```

By the name `PADProduct` and looking at the `Paddle.framework` included in the application directory, we can safely assume that [Paddle](https://www.paddle.com) is being used for payment/subscription management.

Unfortunately, I couldn't find a copy of the SDK to download, so we'll have the reverse the one included with the application.

## Reversing Paddle.framework

To start, let's take a look at the `activated` method:

```Objective-C
char PADProduct::activated(ID self,SEL cmd)
{
  plVar2 = [self licenseController];
  cVar1 = (**(*plVar2 + 0x58))(plVar2);
  return cVar1;
}
```

Hmm, looks like the `licenseController` field is unfortunately a C++ object.

We'll have to make heavy use of the debugger here.

Stepping into that indirect call we find the following function (again self-labeled):

```Objective-C
int __thiscall
Mbo2vpZRt70hoVLvg82RPKlyFkAbc42qmI9cr1Ijdl3az21uFs::is_activated
          (Mbo2vpZRt70hoVLvg82RPKlyFkAbc42qmI9cr1Ijdl3az21uFs *this)
{
  
  licenseCode = this->licenseCode;
  licenseCodeHash = this->licenseCodeHash;
  cVar3 = '\0';

  if ((licenseCode != 0) && (licenseCodeHash != 0)) {
    if (mikWESxEIGeT3Wqgzhvq1euYkBKAVSTwdlSHGNRhAc71yRRwlg()::sCA == 0) {
      buf = __stubs::_malloc(0x40);
      lVar5 = 0;

      do {
        if (lVar5 < 0x40) {
          // Double percent added for string formatting.
          *(buf + lVar5) = "Gd$7*u(w+XxRhJu7s4-99#F%%0[A?Czt4Jr(q2$Vr0@mXP3rQq7FD7+R*-(F/h>_K"[lVar5];
        }
        lVar5 += 1;
      } while (lVar5 != 0x40);

      lVar7 = [[NSString alloc] initWithBytes:buf length:0x40 encoding:1];
      mikWESxEIGeT3Wqgzhvq1euYkBKAVSTwdlSHGNRhAc71yRRwlg()::sCA = lVar7;
    }

    uVar6 = [mikWESxEIGeT3Wqgzhvq1euYkBKAVSTwdlSHGNRhAc71yRRwlg()::sCA dataUsingEncoding:4];

    uVar8 = [NSKeyedArchiver archivedDataWithRootObject:[licenseCode copy]];
    uVar9 = [uVar8 mutableCopy];
    [uVar9 appendData:uVar6];

    uVar8 = uVar9;
    buf = [uVar8 bytes];

    __stubs::_CC_MD5(buf, [uVar8 length], hash);
    uVar9 = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      hash[0],hash[1],hash[2],hash[3],
                      hash[4],hash[5],hash[6],hash[7],
                      hash[8],hash[9],hash[10],hash[11],
                      hash[12],hash[13],hash[14],hash[15]];

    cVar3 = [licenseCodeHash isEqualToString:uVar9];

    if (cVar3 == '\0') {
      uVar7 = [mikWESxEIGeT3Wqgzhvq1euYkBKAVSTwdlSHGNRhAc71yRRwlg()::sCA dataUsingEncoding:4];
      uVar8 = [licenseCode dataUsingEncoding:4];

      uVar6 = [[NSMutableData alloc] initWithData:uVar8];
      [uVar6 appendData:uVar8];

      __stubs::_CC_MD5(uVar6.bytes, uVar6.length, hash);
      uVar6 = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                         hash[0],hash[1],hash[2],hash[3],
                         hash[4],hash[5],hash[6],hash[7],
                         hash[8],hash[9],hash[10],hash[11],
                         hash[12],hash[13],hash[14],hash[15]];

      cVar3 = [licenseCodeHash isEqualToString:uVar6];
    }
  }

  if (*__got::___stack_chk_guard == lVar1) {
    return cVar3;
  }

  __stubs::___stack_chk_fail();
}
```

This function checks if the user's license code matches a saved license code hash when passed through one of two similar hash functions. Both functions take a binary representation of the license code from either`+[NSKeyedArchiver archivedDataWithObject:licenseCode]` or `[licnseCode dataUsingEncoding:4]`.

The second representation tells us that `licenseCode` is an `NSString`.

The first representation uses [NSKeyedArchiver](https://nshipster.com/nscoding/). This, and the `NSCoding` interface serialize/deserialize `NSObject`'s to binary plists. The `encodeWithCoder:` method of an object conforming to `NSCoding` adds (key, value) pairs to the plist.

Searching for methods with this name in the binary shows us a promising class `PADLicenseFile` with such as method:

```Objective-C
void PADLicenseFile::encodeWithCoder:(ID self, SEL cmd, ID encoder)
{
  [encoder encodeObject:self.trialStartDate forKey:@"trialStartDate"];
  [encoder encodeObject:self.licenseCode forKey:@"licenseCode"];
  [encoder encodeObject:self.licenseCodeHash forKey:@"licenseCodeHash"];
  [encoder encodeObject:self.licenseExpiryDate forKey:@"licenseExpiryDate"];
  [encoder encodeObject:self.activationEmail forKey:@"activationEmail"];
  [encoder encodeObject:self.activationID forKey:@"activationId"];
  [encoder encodeObject:self.activationDate forKey:@"activationDate"];
  return;
}
```

Coming back to the hashing algorithm, after the `licenseCode` is converted into binary, a random-looking stirng `"Gd$7*u(w...` is appended to it. The md5 of the resulting byte array is then taken and compared to `licenseCodeHash`.

It doesn't look like any further validation is done on the license code or its hash. Therefore, if we can figure out where to put this information (and which variant of the hashing algorithm is used), we should be able to generate an arbitrary license code and calculate the hash that `Paddle` expects.

## License format on disk

Looking through other methods of the `Mbo2vp...` object, we find another interesting method:

```Objective-C
undefined __thiscall
Mbo2vpZRt70hoVLvg82RPKlyFkAbc42qmI9cr1Ijdl3az21uFs::load_saved_license_data
          (Mbo2vpZRt70hoVLvg82RPKlyFkAbc42qmI9cr1Ijdl3az21uFs *this)
{
                    /* 0x3647c - check_if_spadl_exists */
  cVar4 = (****&this->field_0x50)();

  if (cVar4 == '\0') {
    uVar18 = 0;
  }
  else {
    plVar1 = *&this->field_0x50;
    uVar6 = [*&this->field_0x8 md5];

                    /* 0x365c0 - parse_spadl */
    lVar8 = (**(*plVar1 + 8))(plVar1,uVar6);

    if (lVar8 == 0) {
      uVar18 = 0;
    }
    else {
      uVar6 = [lVar8 objectForKey:@"license_data"];
      this->trialStartDate = [uVar6 trialStartDate];
      this->licenseCode = [uVar6 licenseCode];
      this->licenseCodeHash = [uVar6 licenseCodeHash];

      uVar10 = [uVar6 licenseCode];
      uVar13 = [uVar6 licenseCodeHash];

      /* Same hash calculation from `is_activated */

      this->licenseExpiryDate = [uVar6 licenseExpiryDate];
      this->activationEmail = [uVar6 activationEmail];
      this->activationID = [uVar6 activationId];
      this->activationDate = [uVar6 activationDate];
      uVar18 = 1;
    }
  }

  if (*__got::___stack_chk_guard == local_38) {
    return uVar18;
  }

  __stubs::___stack_chk_fail();
}
```

Of course I already spoiled it, but this method makes two virtual calls.

The first checks if there is a "\<Product ID\>.spadl" file in the "Application Support" directory.

Assuming this file exists, the second method reads the file into an `NSData` object and parses it in the following method:

```Objective-C
void __thiscall
P8r32a46ZpeaYZjCaHlB9hqndX7jzb7jKr8sBLVpKzzaSIIAVu::load_and_decrypt_license_data
          (P8r32a46ZpeaYZjCaHlB9hqndX7jzb7jKr8sBLVpKzzaSIIAVu *this,NSData *param_1,
          NSString *param_2)
{
  uVar5 = [NSKeyedUnarchiver unarchiveObjectWithData:param_1];
  keys[0] = @"license_data";

  uVar6 = [uVar5 objectForKey:keys[0]];
  uVar7 = [uVar6 PADAES256DecryptWithKey:param_2];
  pvVar9 = [NSKeyedUnarchiver unarchiveObjectWithData:uVar7];
  objects[0] = pvVar9;

  keys[1] = @"file_version";
  objects[1] = [uVar6 objectForKey:keys[1]];

  keys[2] = @"sdk_version";
  objects[2] = [uVar6 objectForKey:keys[2]];

  keys[3] = @"file_platform";
  objects[3] = [uVar6 objectForKey:keys[2]];

  uVar8 = [NSDictionary dictionaryWithObjects:objects
                        forKeys:keys
                        count:4];

  if (*__got::___stack_chk_guard == lVar1) {
    return uVar8;
  }

  __stubs::___stack_chk_fail();
}
```

So it looks like the spadl file is actually a keyed archive (binary plist) which contains another AES-encrypted keyed archive which contains the license data:

This key is static so we can just dump it in the debugger and use it to generate our own encrypted keyed archive.

So if we created a keyed archive like so and put it in the correct spadl file, we can successfully unlock the application:

```
NSDictionary:
    file_version: 1
    sdk_version: 1.0
    file_platform: "mac"
    license_data: AES-CBC-256(
        PADLicesneFile:
            trialStartDate: unix epoch time,
            activationStartDate: unix epoch time,
            licenseExpiryDate: 100 years in the future,
            activationEmail: "fakeemail@gmail.com",
            activationID: "fakeuser",
            licenseCode: "A",
            licenseCodeHash: MD5("A" + "Gd$7..."))
```

If we run the application from the command line, we see the following error printed:

`Paddle - verifyActivation - state: 0 error: Optional(Error Domain=com.paddle.paddle Code=-108 "Specifies that we were unable to verify the license activation of a product." UserInfo={NSLocalizedDescription=Specifies that we were unable to verify the license activation of a product.})`

Even though the application "isn't able to verify our license", the app works fine and we can along our merry way.

