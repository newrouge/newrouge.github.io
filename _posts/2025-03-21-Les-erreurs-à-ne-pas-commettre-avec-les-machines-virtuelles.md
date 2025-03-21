---
layout: post
image: /icons/uniseccrypt.png
tags: system
title: Les erreurs à ne pas commettre avec les machines virtuelles
---

Erreurs courantes liées à la virtualisation, et exemples d'exploitation<br>

Lors des tests d'intrusion et des exercices de red team, nous avons constaté que, bien souvent, il était possible de trouver des artefacts de machines virtuelles, des profils actifs, des sauvegardes non chiffrées... Le sujet principal de cet article tourne autour d'une idée : **Le cloisonnement défaillant**.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/loop.png)
{: refdef}

Pourquoi est-ce important, me direz-vous ? D’une part, la hiérarchie des privilèges est censée suivre une structure en arbre. Ainsi, si vous trouvez une boucle dans un arbre, ce n’est jamais bon signe. Mais assez de théorie. Nous allons voir ici des exemples montrant comment exploiter des erreurs de configuration courantes dans les environnements virtualisés. Notez que ces failles ne sont pas spécifiques à une technologie en particulier (VMWare, HyperV, ...) et peuvent s’appliquer à presque toutes.

> **TL;DR**<br>  
> &rarr; Stocker des sauvegardes et disques de machines virtuelles non chiffrés revient à exposer des identifiants en clair<br>  
> &rarr; Gérer les hyperviseurs et les consoles EDR au sein d'Active Directory rompt souvent le cloisonnement<br>  
> &rarr; Lors de l'utilisation d'images disque, de profils utilisateurs ou de sauvegardes, ne pas négliger l'intégrité<br>

# 0. Intro: Tiering

Pour celles et ceux qui ne seraient pas familiers avec le cloisonnement dans Active Directory, ou tiering, voici comment il fonctionne :  

* **Tier 0** : Contient tout ce qui est lié aux contrôleurs de domaine et aux administrateurs du domaine. En principe, il ne devrait être accessible que pour des modifications au niveau du domaine (politiques de mot de passe, GPOs, …).  
* **Tier 1** : Principalement destiné à la gestion des serveurs. Il contient des actifs moins critiques que le niveau précédent, mais représente généralement un risque plus élevé pour l’entreprise.  
* **Tier 2** : Regroupe les postes de travail, téléphones, imprimantes.  

Ce modèle de sécurité est conçu de manière à ce que les administrateurs séparent les rôles et les comptes en fonction du niveau avec lequel ils travaillent. Cela garantit, par exemple, que la compromission d’un ordinateur portable et des comptes connectés dessus ne mène pas immédiatement à la chute de tout le système.

# 1. Unencrypted VM storage

C'est un des exemples les plus courants.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/scrap.png)
{: refdef}

Les sauvegardes de machines virtuelles, snapshots, images et disques virtuels contiennent tous des **secrets**. L’image ci-dessus tente de résumer les types de secrets généralement stockés dans ces fichiers, en s’inspirant librement d’un article de Krebs [Krebs article](https://krebsonsecurity.com/2012/10/the-scrap-value-of-a-hacked-pc-revisited/).  

Il est important de noter que tout secret lié à l’authentification locale, à la configuration d’une application ou à un jeton API utilisé dans un système virtualisé pourrait se retrouver dans un snapshot. Évidemment, exposer ces sauvegardes et disques virtuels (qui ne sont que des fichiers binaires, parfois complexes à analyser mais toujours **lisibles**) sur un réseau avec une authentification et un contrôle d’accès faibles représente un risque majeur.  

Par exemple, un chemin d’attaque très courant pour l’élévation de privilèges dans un réseau contenant des systèmes virtualisés suivrait ces étapes :  

* **Identifier les hyperviseurs**  
* **Identifier les partages contenant des disques et images de machines virtuelles**  
    * Cela peut être fait en recherchant des extensions spécifiques (ex. vhdx, qcow2, …)  
* **Monter/lire les volumes**  
    * Pour `.vhdx`, en utilisant **libguestfs** :  
      ```bash
      guestmount --add vm.vhdx --inspector --ro /mnt/vm/
      ```  
    * Pour `.qcow2` : (ajuster le numéro de partition pour correspondre au système principal)
```bash
modprobe nbd max_part=8
qemu-nbd --connect=/dev/nbd0 vm.qcow2
mount /dev/nbd0p1 /mnt/vm/
```

et paf, les secrets Windows locaux sont lisibles depuis Linux:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/poof.jpg)
{: refdef}

Ceci, couplé avec une mauvaise pratique de réutilisation de mots de passes locaux, peut avoir des effets **dévastateurs**

# 2. Exploiter un mauvais cloisonnement

Comment mentionné précédemment, aucun hyperviseur ne devrait héberger un système d'un niveau supérieur au sien. Voici pourquoi:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/tiering.png)
{: refdef}

Cela crée une élévation de privilèges du niveau 1 au niveau 0. Cela est généralement facilement exploitable, suivant des étapes similaires à celles mentionnées précédemment, mais avec une fin différente :  

* **Identifier les hyperviseurs**  
* **Identifier ceux hébergeant un contrôleur de domaine**  
* **Générer une image de sauvegarde**  
* **Décrypter le fichier NTDS.DIT**  

Mais lors des audits, nous avons principalement utilisé cette boucle dans un autre but : **étendre l'attaque en dehors d'Active Directory**. Par exemple, sur un grand réseau, après avoir obtenu un accès administratif à tous les systèmes d'Active Directory, que reste-t-il à faire ? Auditer les équipements réseau (commutateurs, points d'accès WiFi), accéder aux caméras de surveillance, obtenir un shell root sur les serveurs Linux... <br>  

Eh bien, avec un EDR, cela peut être en réalité simplifié, car il est souvent possible d'exécuter des commandes sur tous les agents locaux en cours d'exécution (même ceux sous Linux) depuis la console principale :

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/edr.png)
{: refdef}

Oui, un EDR est un outil de sécurité, mais l'intégration de tout nouveau système complexifie et **augmente la surface d'attaque**.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/isolate.png)
{: refdef}

Afin d'assurer que ces élévations ne puissent pas être possibles, il est important d'isoler les socles de virtualisation sensibles.


# 3. Porte dérobée active

Ceci est une variante du premier point, mais dans ce cas, nous ciblons une session active d'un utilisateur. Au lieu de parcourir les artefacts des machines virtuelles à la recherche de secrets réutilisables dans l'espoir qu'ils soient toujours valides, nous installons une porte dérobée sur un système actif pour voler les sessions de l'utilisateur :  

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/bd.png)
{: refdef}  

Un exemple concret de cette attaque, qui peut être facilement mis en œuvre en utilisant le plugin multidrop du framework Metasploit :  

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/multidrop.png)
{: refdef}  

Il suffit de remplacer ou d'ajouter des fichiers statiques contenant un chemin UNC sur le bureau de la victime pour voler une session Active Directory active et la rejouer sur le domaine.  

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/vms/bd2.png)
{: refdef}  

Bien qu'il existe de nombreuses contre-mesures à cela (utilisateurs protégés, signature SMB, ...), la meilleure pratique à souligner ici concerne toujours le contrôle d'accès et l'intégrité des images des systèmes virtuels.


# 4. Problème sous côté ?

Nous voyons cela partout. Plus un système est complexe, plus il est probable que des problèmes comme celui-ci apparaissent. Et sachant que HyperV ne prend même pas en charge nativement le chiffrement des disques et des snapshots, il devient très évident que de nombreux administrateurs système ne sont même pas conscients du problème.  

Une piste potentielle qui mérite davantage d'investigation est la possibilité d'ommettre certains fichiers et dossiers des snapshots. Par exemple, ne pas inclure les fichiers SAM, SECURITY ou NTDS.DIT dans les fichiers VHDX améliorerait considérablement la sécurité des systèmes sur site. Pourtant, cela n'est, une fois de plus, pas pris en charge par HyperV.


---
Les erreurs à ne pas commettre avec des machines virtuelles
---
