+++
title = "Static passwords aren't very good - Easy"
date = 2023-05-08
+++

This post features an application that's helpful when studying a performance of a piece of music.

## The Restriction

I downloaded the trial version of the application and was greeted with this message upon startup:

![restriction_message](/track_restriction.png)

## Initial Investigation

The first thing I normally do in this situation is look for the code in the binary that uses that string.

We find in Ghidra that this code in the `doIdle` function references the string:

```C++
iVar2 = CMyOneSecEventLoopTimer::SecondsSinceStart(_g_pCMyOneSecEventLoopTimer);

if ((_g_bRegVersion == '\0') && 
    (2 < iVar2) && 
    (doIdle()::s_bMessageDisplayed == '\0'))
{
  doIdle()::s_bMessageDisplayed = '\x01';
  ShowDialog(
    "This unregistered version will only play track 1 and 2 of a CD and 
     the first quarter  (max 3 minutes) of an audio file."
  );
}
```

So the trial message is displayed when `_g_bRegVersion` is 0.

Looking at the cross references to that symbol, we see that the only place that variable is written to is in a function named `IsPasswordOk`:

```C++
undefined8 IsPasswordOK(void)
{
  __darwin_ct_rune_t _Var1;
  int iVar2;
  size_t sVar3;
  ulong uVar4;
  char local_48 [32];
  long local_28;
  
  local_28 = *__got::___stack_chk_guard;

  pGetEncryptedPassword();
  __stubs::_strcpy(local_48,pGetEncryptedPassword()::szPassword);

  _PDescramblePasswordString(local_48);
  sVar3 = __stubs::_strlen(local_48);

  if (0 < sVar3) 
  {
    uVar4 = 0;
    do {
      _Var1 = __stubs::___tolower(local_48[uVar4]);
      local_48[uVar4] = _Var1;
      uVar4 += 1;
    } while ((sVar3 & 0xffffffff) != uVar4);
  }

  sVar3 = __stubs::_strlen(&_g_szPasswordText);

  if (0 < sVar3) 
  {
    uVar4 = 0;
    do {
      _Var1 = __stubs::___tolower((&_g_szPasswordText)[uVar4]);
      (&_g_szPasswordText)[uVar4] = _Var1;
      uVar4 += 1;
    } while ((sVar3 & 0xffffffff) != uVar4);
  }

  iVar2 = __stubs::_strcmp(local_48,&_g_szPasswordText);

  /* VERSION SET HERE */
  _g_bRegVersion = iVar2 == 0;

  if (*__got::___stack_chk_guard == local_28) {
    return CONCAT71(0x1000ffe,_g_bRegVersion);
  }
                    /* WARNING: Subroutine does not return */
  __stubs::___stack_chk_fail();
}
```

This function compares `pGetEncryptedPassword()::szPassword` to `_g_szPasswordText` and sets `_g_bRegVersion` to true if they are equal.

Taking a look at the `pGetEncryptedPassword` function, we see that this is simply a static string:

```C++
void pGetEncryptedPassword(void)
{
  size_t sVar1;
  
  pGetEncryptedPassword()::szPassword._5_2_ = 0x6975;
  pGetEncryptedPassword()::szPassword[7] = 'j';
  pGetEncryptedPassword()::szPassword[8] = 't';
  pGetEncryptedPassword()::szPassword._9_2_ = 0x7e;
  pGetEncryptedPassword()::szPassword[4] = '\0';
  pGetEncryptedPassword()::szPassword._0_4_ = 0x2e78706c;
  sVar1 = __stubs::_strlen(pGetEncryptedPassword()::szPassword);
  pGetEncryptedPassword()::szPassword[sVar1 + 4] = '\0';
  *(pGetEncryptedPassword()::szPassword + sVar1) = 0x2e7e7863;
  pGetEncryptedPassword()::szPassword[8] = '\0';
  pGetEncryptedPassword()::szPassword[4] = '3';
  pGetEncryptedPassword()::szPassword._5_2_ = 0x3535;
  pGetEncryptedPassword()::szPassword[7] = '.';
  sVar1 = __stubs::_strlen(pGetEncryptedPassword()::szPassword);
  pGetEncryptedPassword()::szPassword[sVar1 + 4] = '\0';
  *(pGetEncryptedPassword()::szPassword + sVar1) = 0x2d396b4c;
  pGetEncryptedPassword()::szPassword[13] = '\0';
  pGetEncryptedPassword()::szPassword._5_2_ = 0x627e;
  pGetEncryptedPassword()::szPassword[7] = 'c';
  pGetEncryptedPassword()::szPassword[8] = 'm';
  pGetEncryptedPassword()::szPassword._9_2_ = 0x7e66;
  pGetEncryptedPassword()::szPassword[11] = 'u';
  pGetEncryptedPassword()::szPassword[12] = '\0';
  pGetEncryptedPassword()::szPassword[4] = '\0';
  pGetEncryptedPassword()::szPassword._0_4_ = 0x532b383b;
  sVar1 = __stubs::_strlen(pGetEncryptedPassword()::szPassword);
  pGetEncryptedPassword()::szPassword[sVar1 + 4] = '\0';
  *(pGetEncryptedPassword()::szPassword + sVar1) = 0x2c2d7e63;
  pGetEncryptedPassword()::szPassword._9_2_ = 0x65;
  pGetEncryptedPassword()::szPassword[8] = '\0';
  pGetEncryptedPassword()::szPassword[4] = 'g';
  pGetEncryptedPassword()::szPassword._5_2_ = 0x3c77;
  pGetEncryptedPassword()::szPassword[7] = ',';
  sVar1 = __stubs::_strlen(pGetEncryptedPassword()::szPassword);
  pGetEncryptedPassword()::szPassword[sVar1 + 4] = '\0';
  *(pGetEncryptedPassword()::szPassword + sVar1) = 0x336f3635;
  pGetEncryptedPassword()::szPassword[8] = '_';
  pGetEncryptedPassword()::szPassword._9_2_ = 0x327a;
  pGetEncryptedPassword()::szPassword[11] = '2';
  pGetEncryptedPassword()::szPassword[12] = 'p';
  pGetEncryptedPassword()::szPassword[13] = '\0';
  return;
}
```

The descramble function is a simple caesar-like rotation but regardless of what the details are, we can set a breakpoint once the function has run and reveal the unscrambled password.

Entering this password into the unlock dialog, we can see that the application has been successfully unlocked:

![static_success](/static_unlock.png)

Easy peasy.
