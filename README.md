# td-ransomware-LBA

# Q1 : Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?

l'algorithme de chiffrement est symétrique (AES). Il utilise des tailles de clé plus longues telles que 128, 192 et 256 bits pour le cryptage. Par conséquent, cela rend l'algorithme AES plus robuste contre le piratage.

# Q2 : Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

on ne peut pas hacher le sel et la clef directement car ils sont des données sensibles et on peut les perdre. HMAC est un code d'authentification de message, qui est destiné à vérifier l'intégrité. 
un bon hashage de mot de passe est un hashage qui est lent à calculer, et qui est difficile à inverser. Et il doit aussi inclure un salt, qui est une chaîne aléatoire ajoutée au mot de passe avant de le hacher. Cela rend le hashage plus robuste contre les attaques, ce qui n'est pas le cas avec un hmac car il n'utilise pas de salt.

# Q3 : Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?


pour éviter de perdre les données du token.bin si on le supprime par erreur ou si on le modifie par erreur. Et aussi pour éviter que le programme ne s'arrête si le token.bin est déjà présent.


# Q4 : Comment vérifier que la clef la bonne ?

on vérifie que la clef est bonne en la décodant en base64 et en vérifiant que la taille de la clef est bien de 32 octets (256 bits) et que la clef est bien de type bytes et non de type str. 


# B1 : Expliquez ce que vous faite et pourquoi

on fait une boucle sur les fichiers à voler et on les envoie au cnc. on fait ça pour que les fichiers soient envoyés au cnc un par un et non tous en même temps. Et on fait ça pour éviter que le cnc ne soit surchargé.


# B2 : Expliquez comment le casser et écrivez un script pour récupérer la clef à partir d’un fichier

on peut casser le chiffrement en utilisant la méthode de chiffrement par blocs. on récupère la clef à partir d'un fichier chiffré et d'un fichier clair.

# B3 : quelle(s) option(s) vous est(sont) offerte(s) fiable(s) par la bibliothèque cryptographie ?

on a plusiers options fiables par la bibliothèque cryptographie. on a l'option de chiffrement par blocs qui est fiable car elle permet de récupérer la clef à partir d'un fichier chiffré et d'un fichier clair. on a aussi l'option de chiffrement par flux. 

 








