@echo off
cd /d C:\Users\nashp\EscoConcepts_Backend
set GIT_TERMINAL_PROMPT=0
set GIT_ASK_YESNO=false
echo Running Git garbage collection...
git gc --auto
echo Adding all changes...
git add .
echo Committing...
git commit -m "Auto update %date% %time%"
echo Pushing to GitHub...
git push -u origin main
echo Done!
pause