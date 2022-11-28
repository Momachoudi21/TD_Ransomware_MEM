# td-ransomware-LBA

Q1 : Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?

l'algorithme de chiffrement est AES-256, il est robuste car il est utilisé par les banques et les gouvernements.

Q2 : Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

on ne peut pas hacher le sel et la clef directement car le sel et la clef sont des données sensibles et on ne peut pas les hacher car on ne peut pas les retrouver. On utilise un hmac pour hacher le sel et la clef. avec un hmac on peut retrouver le sel et la clef.
le hmac est un algorithme de hachage qui permet de hacher des données sensibles.

Q3 : Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?

pour éviter de perdre les données du token.bin si on le supprime par erreur ou si on le modifie par erreur et pour éviter de perdre les données du token.bin. d'autre part si on a déjà un token.bin on ne peut pas en créer un autre.


Une fois les éléments cryptographiques chargés, il est possible de charger une clef qui serait
fournie par la victime. Mais avant de définir la variable self._key de SecretManager, il est impératif
de la valider, sans quoi les fichiers seraient déchiffré avec la mauvaise clef …
La clef sera fournie en base64 (c’est une clef binaire originalement). Si la clef n’est pas bonne,
vous devez levez une exception.
Q4 : Comment vérifier que la clef la bonne ?

on vérifie que la clef est bonne en la décodant en base64 et en vérifiant que la taille de la clef est bien de 32 octets (256 bits) et que la clef est bien de type bytes et non de type str. si la clef n'est pas bonne on lève une exception.

Une bonne politique de sécurité implique de faire régulièrement des sauvegardes, à chaud et à
froid. Ce dernier point implique, par exemple, un disque dure USB donc hors d’atteinte. Cela
casse donc votre modèle économique. Un bon moyen est de revendre à votre victime ses propres
données : personne n’a envie de voir ses listing clients, sa compta ou les feuilles de payes être mis
en place publique. Ou pire encore.
Une solution est d’ajouter une fonction leak_files(self, files:List[str])->None dans la
classe SecretManager , devant envoyer les fichiers au CNC (ex : post_file(self, path:str,
params:dict, body:dict)->dict ).
B1 : Expliquez ce que vous faite et pourquoi

on fait une boucle sur les fichiers à voler et on les envoie au cnc. on fait ça pour que les fichiers soient envoyés au cnc et que les fichiers soient volés et que les fichiers soient envoyés au cnc.

Le chiffrement proposé est peut être … perfectible.
B2 : Expliquez comment le casser et écrivez un script pour récupérer la clef à partir d’un fichier
chiffré et d’un fichier clair.

on peut casser le chiffrement en utilisant la méthode de chiffrement par blocs. on récupère la clef à partir d'un fichier chiffré et d'un fichier clair en utilisant la méthode de chiffrement par blocs.

B3 : quelle(s) option(s) vous est(sont) offerte(s) fiable(s) par la bibliothèque cryptographie ?
Justifiez
on a plusiers options fiables par la bibliothèque cryptographie. on a l'option de chiffrement par blocs qui est fiable car elle permet de récupérer la clef à partir d'un fichier chiffré et d'un fichier clair. on a aussi l'option de chiffrement par flux qui est fiable car elle permet de récupérer la clef à partir d'un fichier chiffré et d'un fichier clair.

B4 : Implémentez votre solution.






