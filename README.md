# pen300

`DISCLAIMER: THIS REPO CONTAINS CODE THAT MAYBE FLAGGED AS MALWARE BY WINDOWS DEFENDER. PEN300 is about malware evasion techniques. what else did you expect? :) ITS BETTER TO ADD EXCLUSIONS FOR THIS FOLDER BEFORE OPENING THE REPO IF YOU KNOW WHAT YOU ARE DOING.`

Repository for doing pen300 exercises.
Need to start with book.

Will add multiple folders for various blogs/ resources.

Look inside book folder for more info.

Also what about this tweet

```
https://twitter.com/C5pider/status/1555256779553906694
```

# ON reddit about OSEP 

https://www.reddit.com/r/osep/comments/uwv0k1/failed_with_2_flags_but_im_hopeful/

Cant go over specifics regarding any vulnerabilities but I do have tips that should increase your chances of success, keeping this as spoiler free as possible per the academic policy:

Automate as much of your tooling as possible. This includes things like building stagers, standing up your c2, generating certificates, network enumeration (ideally supporting socks), etc. The lab environment is hard enough so try to minimize as much repetitive tasks as possible. You live or die based on your tooling.

If you cant bypass AV, you might want to wait before taking the exam. You will more than likely fail. Make sure you practice AV evasion and make good, vetted stagers. Once you're sure your stuff passes AV, then you're ready to attempt the exam.

Don't expect the scenario to match the challenges at all. I cannot stress this enough. While the challenges are good practice, you're setting yourself up for failure if you use that as your only means of preparation. Regarding this point, the exam felt like a bait and switch when compared to the course material.

Regarding environments that are similar to the scenarios, I would suggest cybernetics, or the offensive security proving grounds network exercises.

Test your tooling on multiple different kinds of windows devices. Just because your tool works on Windows XX does not mean it will work on Windows Server XXXX.

Make sure you're very familiar with Lolbas, which are lightly mentioned but not covered too in depth in the course: https://lolbas-project.github.io/

Bearing point 3 in mind, enumerate like crazy. I can't stress this point enough.

Be very familiar with testing remote code in a blind context. Remember, anything that produces network traffic like ping, curl, Active X components, powershell iwr, etc. are your friend.

Don't make assumptions about what endpoint protections are being used on a given machine. Enumerate as much as you can, blindly if you have to




