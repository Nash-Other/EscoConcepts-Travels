@echo off
cd /d C:\Users\nashp\EscoConcepts_Backend
echo Adding all changes...
git add .
echo Committing...
git commit -m "Auto update %date% %time%"
echo Pushing to GitHub...
git push
echo Done!
pause