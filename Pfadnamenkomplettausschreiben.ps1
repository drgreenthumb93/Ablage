### Powershell Pfadnamen komplett ausschreiben lassen

Get-Childitem -Path "C:\Pfad\zum\Verzeichnis\" -recurse -directory (entweder File oder Directory) -force -ErrorAction SilentlyContinue | ft Fullname, CreationDate, LastAccessTime -Wrap | Out-file -Filepath C:\Pfad\zum\Ausgabeverzeichnis\*.txt
