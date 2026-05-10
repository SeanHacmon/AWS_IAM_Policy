{\rtf1\ansi\ansicpg1252\cocoartf2709
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\froman\fcharset0 Times-Bold;\f1\froman\fcharset0 Times-Roman;\f2\fmodern\fcharset0 Courier;
\f3\fnil\fcharset0 Menlo-Regular;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;\red109\green109\blue109;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;\cssrgb\c50196\c50196\c50196;}
{\*\listtable{\list\listtemplateid1\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid1\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid1}
{\list\listtemplateid2\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid101\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid2}
{\list\listtemplateid3\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid201\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid3}
{\list\listtemplateid4\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid301\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid4}}
{\*\listoverridetable{\listoverride\listid1\listoverridecount0\ls1}{\listoverride\listid2\listoverridecount0\ls2}{\listoverride\listid3\listoverridecount0\ls3}{\listoverride\listid4\listoverridecount0\ls4}}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\deftab720
\pard\pardeftab720\sa321\partightenfactor0

\f0\b\fs48 \cf0 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 IAM Policy Classification Engine - Setup & Run Guide\
\pard\pardeftab720\sa298\partightenfactor0

\fs36 \cf0 Prerequisites\
\pard\tx220\tx720\pardeftab720\li720\fi-720\partightenfactor0
\ls1\ilvl0
\f1\b0\fs24 \cf0 \kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Python 3.9 or higher\
\ls1\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 A Groq API key (free at https://console.groq.com)\
\pard\pardeftab720\partightenfactor0
\cf0 \
\pard\pardeftab720\sa298\partightenfactor0

\f0\b\fs36 \cf0 Part 1 - Memory Management Simulation\
\pard\pardeftab720\sa280\partightenfactor0

\fs28 \cf0 No external dependencies required.\
How to run\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 # Demonstrate the exploit (attack + security check + performance benchmark)\
python3 attack_demo.py\
\
# Run all unit tests\
python3 -m unittest test.py -v\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 Expected output\
\pard\tx220\tx720\pardeftab720\li720\fi-720\partightenfactor0
\ls2\ilvl0
\f1\b0\fs24 \cf0 \kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 RAM state before and after the attack\
\ls2\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Security check: Page 50 eviction rate over 100 trials\
\ls2\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Performance benchmark: fault rate comparison between original and patched algorithm\
\pard\pardeftab720\partightenfactor0
\cf0 \
\pard\pardeftab720\sa298\partightenfactor0

\f0\b\fs36 \cf0 Part 2 - AWS IAM Policy Classification Engine\
\pard\pardeftab720\sa280\partightenfactor0

\fs28 \cf0 Install dependencies\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 pip install groq\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 Set your Groq API key\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 # macOS / Linux\
export GROQ_API_KEY=your_key_here\
\
# Windows (Command Prompt)\
set GROQ_API_KEY=your_key_here\
\
# Windows (PowerShell)\
$env:GROQ_API_KEY="your_key_here"\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 How to run\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 # Run the full evaluation on all 9 labeled policies\
python3 eval.py\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 Expected output\
\pard\tx220\tx720\pardeftab720\li720\fi-720\partightenfactor0
\ls3\ilvl0
\f1\b0\fs24 \cf0 \kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Classification table (9 policies, expected vs got, score, time)\
\ls3\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 100% agreement rate\
\ls3\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Detailed findings per policy\
\ls3\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Fixed policies saved to output_policies/\
\ls3\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Full results saved to eval_results.json\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 File structure required\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 your_folder/\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  agent.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  tools.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  criteria.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  eval.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  policies/\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9500 \u9472 \u9472 
\f2  weak_1.json ... weak_4.json\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9500 \u9472 \u9472 
\f2  strong_1.json ... strong_3.json\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9500 \u9472 \u9472 
\f2  edge_1.json\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9492 \u9472 \u9472 
\f2  score_3.json\
\pard\pardeftab720\partightenfactor0

\f1\fs24 \cf0 \
\pard\pardeftab720\sa298\partightenfactor0

\f0\b\fs36 \cf0 Part 3 - GCP IAM Policy Classification (Bonus)\
\pard\pardeftab720\sa280\partightenfactor0

\fs28 \cf0 No additional dependencies beyond Part 2.\
How to run\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 # Make sure GROQ_API_KEY is still set (same as Part 2)\
python3 gcp_demo.py\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 Expected output\
\pard\tx220\tx720\pardeftab720\li720\fi-720\partightenfactor0
\ls4\ilvl0
\f1\b0\fs24 \cf0 \kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 GCP to AWS translation example\
\ls4\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Classification table (6 GCP policies)\
\ls4\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 100% agreement rate\
\ls4\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Detailed findings per policy\
\ls4\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	\uc0\u8226 	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Results saved to gcp_eval_results.json\
\pard\pardeftab720\sa280\partightenfactor0

\f0\b\fs28 \cf0 File structure required\
\pard\pardeftab720\partightenfactor0

\f2\b0\fs26 \cf0 your_folder/\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  agent.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  tools.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  criteria.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  gcp_adapter.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  gcp_classifier.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  gcp_demo.py\

\f3 \uc0\u9500 \u9472 \u9472 
\f2  gcp_policies/\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9500 \u9472 \u9472 
\f2  gcp_weak_1.json ... gcp_weak_3.json\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9500 \u9472 \u9472 
\f2  gcp_strong_1.json, gcp_strong_2.json\

\f3 \uc0\u9474 
\f2    
\f3 \uc0\u9492 \u9472 \u9472 
\f2  gcp_edge_1.json\
\pard\pardeftab720\partightenfactor0

\f1\fs24 \cf0 \
\pard\pardeftab720\sa298\partightenfactor0

\f0\b\fs36 \cf0 Quick Reference\

\itap1\trowd \taflags0 \trgaph108\trleft-108 \trbrdrt\brdrnil \trbrdrl\brdrnil \trbrdrr\brdrnil 
\clvertalc \clshdrawnil \clwWidth2186\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx2880
\clvertalc \clshdrawnil \clwWidth4680\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx5760
\clvertalc \clshdrawnil \clwWidth2360\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx8640
\pard\intbl\itap1\pardeftab720\qc\partightenfactor0

\fs24 \cf0 Part\cell 
\pard\intbl\itap1\pardeftab720\qc\partightenfactor0
\cf0 Command\cell 
\pard\intbl\itap1\pardeftab720\qc\partightenfactor0
\cf0 Key dependency\cell \row

\itap1\trowd \taflags0 \trgaph108\trleft-108 \trbrdrl\brdrnil \trbrdrr\brdrnil 
\clvertalc \clshdrawnil \clwWidth2186\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx2880
\clvertalc \clshdrawnil \clwWidth4680\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx5760
\clvertalc \clshdrawnil \clwWidth2360\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx8640
\pard\intbl\itap1\pardeftab720\partightenfactor0

\f1\b0 \cf0 Part 1 \'97 exploit demo\cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0

\f2\fs26 \cf0 python3 attack_demo.py
\f1\fs24 \cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 none\cell \row

\itap1\trowd \taflags0 \trgaph108\trleft-108 \trbrdrl\brdrnil \trbrdrr\brdrnil 
\clvertalc \clshdrawnil \clwWidth2186\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx2880
\clvertalc \clshdrawnil \clwWidth4680\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx5760
\clvertalc \clshdrawnil \clwWidth2360\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx8640
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 Part 1 \'97 unit tests\cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0

\f2\fs26 \cf0 python3 -m unittest test.py -v
\f1\fs24 \cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 none\cell \row

\itap1\trowd \taflags0 \trgaph108\trleft-108 \trbrdrl\brdrnil \trbrdrr\brdrnil 
\clvertalc \clshdrawnil \clwWidth2186\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx2880
\clvertalc \clshdrawnil \clwWidth4680\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx5760
\clvertalc \clshdrawnil \clwWidth2360\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx8640
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 Part 2 \'97 eval\cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0

\f2\fs26 \cf0 python3 eval.py
\f1\fs24 \cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 groq, GROQ_API_KEY\cell \row

\itap1\trowd \taflags0 \trgaph108\trleft-108 \trbrdrl\brdrnil \trbrdrt\brdrnil \trbrdrr\brdrnil 
\clvertalc \clshdrawnil \clwWidth2186\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx2880
\clvertalc \clshdrawnil \clwWidth4680\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx5760
\clvertalc \clshdrawnil \clwWidth2360\clftsWidth3 \clmart10 \clmarl10 \clmarb10 \clmarr10 \clbrdrt\brdrnil \clbrdrl\brdrnil \clbrdrb\brdrnil \clbrdrr\brdrnil \clpadt20 \clpadl20 \clpadb20 \clpadr20 \gaph\cellx8640
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 Part 3 \'97 GCP bonus\cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0

\f2\fs26 \cf0 python3 gcp_demo.py
\f1\fs24 \cell 
\pard\intbl\itap1\pardeftab720\partightenfactor0
\cf0 groq, GROQ_API_KEY\cell \lastrow\row
}
