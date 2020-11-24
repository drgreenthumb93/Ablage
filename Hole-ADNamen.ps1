$OUpath = 'dc=company,dc=de'
$ExportPath = 'C:\Temp\AD_Namen.csv'
Get-ADUser -Filter * -SearchBase $OUpath | 
Select-object DistinguishedName,Name,UserPrincipalName | Export-Csv -NoType $ExportPath
