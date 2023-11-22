##############################################################################
#
# VERSION 2.0
# Nov. 2023
#
# Genera usuarios para examenes, oposiciones o cortesia
#
#############################################################################


##############################################################################
# FUNCION New-Passwd
#
#         Genera una password basada en sílabas más legible
#
# PARAMETROS:
#               Longitud de las sílabas
##############################################################################

function New-Passwd($Length) 
{

    Begin {
        #consonants except hard to speak ones
        [Char[]]$lowercaseConsonants = "bcdfghjklmnprstv"
        [Char[]]$uppercaseConsonants = "BCDFGHJKLMNPRSTV"
        #vowels
        [Char[]]$lowercaseVowels = "aeiou"
        #both
        $lowercaseConsantsVowels = $lowercaseConsonants+$lowercaseVowels
        #numbers
        [Char[]]$numbers = "23456789"
        #special characters
        [Char[]]$specialCharacters = '!$.+&?:_%>-*'

        $countNum = 0
    }
    Process {
            $script:Passwd = ''
            #random location for special char between first syllable and length
            $specialCharSpot = Get-Random -Minimum 1 -Maximum $Length
            for ($i=0; $i -lt $Length; $i++) {
                if ($i -eq $specialCharSpot) {
                    #add a special char
                    $script:Passwd += ($specialCharacters | Get-Random -Count 1)
                }
                #Start with uppercase
                if ($i -eq 0) {
                    $script:Passwd += ($uppercaseConsonants | Get-Random -Count 1)
                } else {
                    $script:Passwd += ($lowercaseConsonants | Get-Random -Count 1)
                }
                $script:Passwd += ($lowercaseVowels | Get-Random -Count 1)
                $script:Passwd += ($lowercaseConsantsVowels | Get-Random -Count 1)
            }
            #add a number at the end
            $randNumNum = Get-Random -Minimum 3 -Maximum 4
            $script:Passwd += (($numbers | Get-Random -Count $randNumNum)-join '')
            return $script:Passwd
    }
}

##############################################################################
# FUNCION generateRandomPassword
#
#         Eso
#
# PARAMETROS:
#               Ninguno
##############################################################################

function generateRandomPassword()
    {
        $alphabet = 'abcdefghijkmnpqrstuvwxyz23456789!$%&/()=,.-_:;+*'
        $numbers = '23456789'
        $chars = '=,.-_*'
        $pass = [char[]]::new(10)
        $alphaLength = $alphabet.length - 1
        for ($i = 0; $i -lt 10; $i++) {
            $n = Get-Random -Minimum 0 -Maximum $alphaLength
            $pass[$i] = $alphabet[$n]
        }
        return $pass -join ""
    }

##############################################################################
# FUNCION goUndo
#
#         Deshace la última creación hecha
#
# PARAMETROS:
#               fichero cue para deshacer
##############################################################################
function doUndo($undoFile,$HomeBase)
{
    #Recupera la lista de usuarios del fichero
    $userList = Import-Csv $undoFile -Delimiter "-" -Header user,password
    foreach( $user in $userList.user )
    {
        $user = $user.Trim()
        $homePath = $HomeBase + $user
        
        #Comprobamos que existe
        if (-Not (Test-Path $homePath))
        {
            Write-Host "No existe el home de los usuarios en " + $HomeBase + " ¿Seguro que el tipo de cuenta está bien?" -ForegroundColor Red
            Exit
        }
        #Borramos el home
        Remove-Item -Recurse -Force $homePath
        #Borramos el usuario
        Remove-ADUser -Identity $user -Confirm:$false
        Write-Host "Borrado $user" -ForegroundColor Green
    }
}

##############################################################################
# FUNCION createUser
#
#         Crea un usuario en AD
#
# PARAMETROS:
#               username, password
##############################################################################

function createUser($username,$password)
{
    $securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    New-ADUser -Name $username -AccountPassword $securePassword -CannotChangePassword $True -Enabled $True -Description "Creado por CreaCuentasExamen PS"
    Add-ADGroupMember -Identity "UCOUSERS" -Members $username
}

##############################################################################
# FUNCION createHome
#
#         Crea el home de un usuario
#
# PARAMETROS:
#               username
##############################################################################

function createHome($username,$HomeBase)
{
    $homePath = $HomeBase+$username
    $adUser = "UCO\"+$username
    New-Item -Path $homePath -ItemType Directory
    $acl = Get-Acl $homePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adUser,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    (Get-Item $homePath).SetAccessControl($acl)
}

##########################################
# PROGRAMA PRINCIPAL
##########################################
Import-Module ActiveDirectory

Set-Location (Split-Path $MyInvocation.MyCommand.Path)

#Preguntamos por el tipo de cuenta a crear

Write-Host "¿Que tipo de cuenta desea procesar? (E)xamen (O)posiciones (C)ortesia: " -ForegroundColor Yellow -NoNewline 
$type = Read-Host
switch -Wildcard ($type)
{
    "E" {$HomeBase = "\\cifs\EXAMENES$\"}
    "C" {$HomeBase = "\\cifs\CORTESIA$\"}
    "O" {$HomeBase = "\\cifs\OPOSICIONES$\"}
    default
    {
        Write-Host "Error: Debe escoger entre E, O ó C" -ForegroundColor Red
        Exit
    }
}

$typeString = [regex]::Match($HomeBase, '\\\\.+\\(.+)\$').Groups[1].Value
Write-Host "Trabajando con cuentas de $typeString" -ForegroundColor Green

Write-Host "Desea deshacer una operación (sS) " -ForegroundColor Yellow -NoNewline 
$undo = Read-Host 
if($undo -like "S")
{
    do
    {
        #Recupera todos los ficheros de cuentas del directorio
        Get-ChildItem -Filter "*.cue"
        $undoFile = Read-Host -Prompt "Nombre de fichero a deshacer (qQ para salir)"
        if($undoFile -like "Q")
        {
            exit
        }
        if(Test-Path   $undoFile -PathType Leaf)
        {
            Write-Host "Ha seleccionado $undoFile está seguro que quiere deshacer (sS) " -NoNewline -ForegroundColor Yellow
            $sure = Read-Host 
            if($sure -like "S")
            {
                doUndo $undoFile $HomeBase
                exit
            }
        }
        else
        {
            Write-Host "El fichero tecleado no existe, repita" -fore red
        }
    } while($true)
}
else
{

    $prefix = Read-Host -Prompt "Prefijo de las cuentas"
    [uint16]$amount = Read-Host -Prompt "Numero total de cuentas"
    [uint16]$start = Read-Host -Prompt "Indice de la primera cuenta"
    $padlength = 8 - $prefix.Length

    $salFile = $prefix + ".cue"

    #Creamos el fichero de salida
    Out-File -FilePath $salFile

    for($i=$start;$i -lt $start+$amount;$i++)
    {
      $suffix = $i.ToString()
      $password = New-Passwd(2)
      $username = $prefix + $suffix.PadLeft($padlength,"0")
      Write-Host  "Creando " $username "-" $password
     
      createUser $username $password
      createHome $username $HomeBase
      #Grabamos en el fichero
      $username+" - "+$password | Add-Content $salFile
    }
}

  