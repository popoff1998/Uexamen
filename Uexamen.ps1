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
        $alphabet = 'abcdefghijklmnopqrstuvwxyz1234567890!$%&/()=,.-_:;+*'
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
function doUndo($undoFile)
{
    #Recupera la lista de usuarios del fichero
    $userList = Import-Csv $undoFile -Delimiter "-" -Header user,password
    foreach( $user in $userList.user )
    {
        $user = $user.Trim()
        $homePath = "\\cifs\especiales$\EXAMEN\"+$user
      
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

function createHome($username)
{
    $homePath = "\\cifs\especiales$\EXAMEN\"+$username
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

Write-Host "Desea deshacer una operación (sS)" -ForegroundColor Yellow -NoNewline 
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
            Write-Host "Ha seleccionado $undoFile está seguro que quiere deshacer (sS)" -NoNewline -ForegroundColor Yellow
            $sure = Read-Host 
            if($sure -like "S")
            {
                doUndo $undoFile
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
      $password = generateRandomPassword
      $username = $prefix + $suffix.PadLeft($padlength,"0")
      Write-Host  "Creando " $username "-" $password
     
      createUser $username $password
      createHome $username
      #Grabamos en el fichero
      $username+" - "+$password | Add-Content $salFile
    }
}

  