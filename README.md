# pdf_brute_force_sbi

I am done with this awful bank called State Bank of India (SBI). They send account statement as locked pdf saying password is combination of Last five digits of phone number and birthdate in DDMMYY format. But if you try that to your business or joint account, it simply doens't work. Thus I have created simple tool using multiprocessing to brute force password.

To run script use following command:

```python brute.py <PDF_FILE_PATH> --prefix <FIRST_5_DIGITS> --suffix <LAST_6_DIGITS> --processes <NUM_PROCESSES>```

--prefix --suffix is optional. prefix contains your phone number if you know or suffix conatins your date of birth.

