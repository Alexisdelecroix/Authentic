# Projet d'Authentification Sécurisée


## Contexte du projet!


Dans le cadre de ce projet, nous avons pour mission de créer une API d'authentification sécurisée visant à permettre aux administrateurs de s'inscrire et de se connecter de manière fiable et sécurisée. 
Cette authentification est cruciale dans le développement d'applications web, car elle garantit que seules les personnes autorisées peuvent accéder aux fonctionnalités et aux données sensibles de l'application.

## Voici les détails :

1) Enregistrement Sécurisé des Administrateurs :

Notre API permettra aux administrateurs de s'inscrire en fournissant leur adresse e-mail autorisée et un mot de passe robuste. L'adresse e-mail sera soumise à une validation pour s'assurer de sa légitimité. 
Le mot de passe sera soumis à un processus de hachage sécurisé avant d'être stocké dans notre base de données. Un jeton JWT (JSON Web Token) sera généré pour chaque administrateur inscrit, ce qui permettra une authentification ultérieure.

2) Connexion Sécurisée :

Les administrateurs pourront se connecter en fournissant leurs informations d'identification (adresse e-mail et mot de passe). 
Le système vérifiera la correspondance entre le mot de passe fourni et le hachage stocké en base de données. Si les informations sont valides, un nouveau jeton JWT sera généré et renvoyé à l'administrateur pour une utilisation ultérieure.

3) Protection des Routes avec des Tokens JWT :

Les routes sensibles de l'API seront protégées grâce à l'utilisation de tokens JWT. Lorsqu'un administrateur tente d'accéder à ces routes, le système vérifiera la validité du jeton JWT inclus dans l'en-tête de la requête. 
Cela garantira que seuls les administrateurs authentifiés et disposant d'un jeton valide peuvent accéder à ces zones protégées.

