<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Validation Language Lines
    |--------------------------------------------------------------------------
    |
    | The following language lines contain the default error messages used by
    | the validator class. Some of these rules have multiple versions such
    | as the size rules. Feel free to tweak each of these messages here.
    |
    */

    'accepted' => 'Le champ :attribute doit être accepté.',
    'accepted_if' => 'Le champ :attribute doit être accepté quand :other est :value.',
    'active_url' => 'Le champ :attribute n\'est pas une URL valide.',
    'after' => 'Le champ :attribute doit être une date postérieure au :date.',
    'after_or_equal' => 'Le champ :attribute doit être une date postérieure ou égale au :date.',
    'alpha' => 'Le champ :attribute doit contenir uniquement des lettres.',
    'alpha_dash' => 'Le champ :attribute doit contenir uniquement des lettres, des chiffres et des tirets.',
    'alpha_num' => 'Le champ :attribute doit contenir uniquement des lettres et des chiffres.',
    'array' => 'Le champ :attribute doit être un tableau.',
    'before' => 'Le champ :attribute doit être une date antérieure au :date.',
    'before_or_equal' => 'Le champ :attribute doit être une date antérieure ou égale au :date.',
    'between' => [
        'numeric' => 'Le champ :attribute doit être compris entre :min et :max.',
        'file' => 'Le fichier :attribute doit avoir une taille entre :min et :max kilo-octets.',
        'string' => 'Le champ :attribute doit contenir entre :min et :max caractères.',
        'array' => 'Le tableau :attribute doit contenir entre :min et :max éléments.',
    ],
    'boolean' => 'Le champ :attribute doit être vrai ou faux.',
    'confirmed' => 'La confirmation du champ :attribute ne correspond pas.',
    'current_password' => 'Le mot de passe est incorrect.',
    'date' => 'Le champ :attribute n\'est pas une date valide.',
    'date_equals' => 'Le champ :attribute doit être une date égale à :date.',
    'date_format' => 'Le champ :attribute ne correspond pas au format :format.',
    'declined' => 'Le champ :attribute doit être refusé.',
    'declined_if' => 'Le champ :attribute doit être refusé quand :other est :value.',
    'different' => 'Les champs :attribute et :other doivent être différents.',
    'digits' => 'Le champ :attribute doit contenir :digits chiffres.',
    'digits_between' => 'Le champ :attribute doit contenir entre :min et :max chiffres.',
    'dimensions' => 'Les dimensions de l\'image :attribute ne sont pas valides.',
    'distinct' => 'Le champ :attribute a une valeur en double.',
    'email' => 'Le champ :attribute doit être une adresse email valide.',
    'ends_with' => 'Le champ :attribute doit se terminer par l\'une des valeurs suivantes : :values.',
    'enum' => 'La valeur sélectionnée pour :attribute est invalide.',
    'exists' => 'La valeur sélectionnée pour :attribute est invalide.',
    'file' => 'Le champ :attribute doit être un fichier.',
    'filled' => 'Le champ :attribute doit avoir une valeur.',
    'gt' => [
        'numeric' => 'Le champ :attribute doit être supérieur à :value.',
        'file' => 'Le fichier :attribute doit être supérieur à :value kilo-octets.',
        'string' => 'Le champ :attribute doit contenir plus de :value caractères.',
        'array' => 'Le tableau :attribute doit contenir plus de :value éléments.',
    ],
    'gte' => [
        'numeric' => 'Le champ :attribute doit être supérieur ou égal à :value.',
        'file' => 'Le fichier :attribute doit être supérieur ou égal à :value kilo-octets.',
        'string' => 'Le champ :attribute doit contenir au moins :value caractères.',
        'array' => 'Le tableau :attribute doit contenir au moins :value éléments.',
    ],
    'image' => 'Le champ :attribute doit être une image.',
    'in' => 'La valeur sélectionnée pour :attribute est invalide.',
    'in_array' => 'Le champ :attribute n\'existe pas dans :other.',
    'integer' => 'Le champ :attribute doit être un entier.',
    'ip' => 'Le champ :attribute doit être une adresse IP valide.',
    'ipv4' => 'Le champ :attribute doit être une adresse IPv4 valide.',
    'ipv6' => 'Le champ :attribute doit être une adresse IPv6 valide.',
    'json' => 'Le champ :attribute doit être une chaîne JSON valide.',
    'lt' => [
        'numeric' => 'Le champ :attribute doit être inférieur à :value.',
        'file' => 'Le fichier :attribute doit être inférieur à :value kilo-octets.',
        'string' => 'Le champ :attribute doit contenir moins de :value caractères.',
        'array' => 'Le tableau :attribute doit contenir moins de :value éléments.',
    ],
    'lte' => [
        'numeric' => 'Le champ :attribute doit être inférieur ou égal à :value.',
        'file' => 'Le fichier :attribute doit être inférieur ou égal à :value kilo-octets.',
        'string' => 'Le champ :attribute doit contenir au maximum :value caractères.',
        'array' => 'Le tableau :attribute doit contenir au maximum :value éléments.',
    ],
    'mac_address' => 'Le champ :attribute doit être une adresse MAC valide.',
    'max' => [
        'numeric' => 'Le champ :attribute ne peut pas être supérieur à :max.',
        'file' => 'Le fichier :attribute ne peut pas être supérieur à :max kilo-octets.',
        'string' => 'Le champ :attribute ne peut pas contenir plus de :max caractères.',
        'array' => 'Le tableau :attribute ne peut pas contenir plus de :max éléments.',
    ],
    'mimes' => 'Le champ :attribute doit être un fichier de type : :values.',
    'mimetypes' => 'Le champ :attribute doit être un fichier de type : :values.',
    'min' => [
        'numeric' => 'Le champ :attribute doit être au moins :min.',
        'file' => 'Le fichier :attribute doit être au moins :min kilo-octets.',
        'string' => 'Le champ :attribute doit contenir au moins :min caractères.',
        'array' => 'Le tableau :attribute doit contenir au moins :min éléments.',
    ],
    'multiple_of' => 'Le champ :attribute doit être un multiple de :value.',
    'not_in' => 'La valeur sélectionnée pour :attribute est invalide.',
    'not_regex' => 'Le format du champ :attribute est invalide.',
    'numeric' => 'Le champ :attribute doit être un nombre.',
    'password' => 'Le mot de passe est incorrect.',
    'present' => 'Le champ :attribute doit être présent.',
    'prohibited' => 'Le champ :attribute est interdit.',
    'prohibited_if' => 'Le champ :attribute est interdit quand :other est :value.',
    'prohibited_unless' => 'Le champ :attribute est interdit sauf si :other est dans :values.',
    'prohibits' => 'Le champ :attribute interdit :other d\'être présent.',
    'regex' => 'Le format du champ :attribute est invalide.',
    'required' => 'Le champ :attribute est obligatoire.',
    'required_array_keys' => 'Le champ :attribute doit contenir des entrées pour : :values.',
    'required_if' => 'Le champ :attribute est obligatoire quand :other est :value.',
    'required_unless' => 'Le champ :attribute est obligatoire sauf si :other est dans :values.',
    'required_with' => 'Le champ :attribute est obligatoire quand :values est présent.',
    'required_with_all' => 'Le champ :attribute est obligatoire quand :values sont présents.',
    'required_without' => 'Le champ :attribute est obligatoire quand :values n\'est pas présent.',
    'required_without_all' => 'Le champ :attribute est obligatoire quand aucun de :values n\'est présent.',
    'same' => 'Les champs :attribute et :other doivent correspondre.',
    'size' => [
        'numeric' => 'Le champ :attribute doit être :size.',
        'file' => 'Le fichier :attribute doit être de :size kilo-octets.',
        'string' => 'Le champ :attribute doit contenir :size caractères.',
        'array' => 'Le tableau :attribute doit contenir :size éléments.',
    ],
    'starts_with' => 'Le champ :attribute doit commencer par l\'une des valeurs suivantes : :values.',
    'string' => 'Le champ :attribute doit être une chaîne de caractères.',
    'timezone' => 'Le champ :attribute doit être un fuseau horaire valide.',
    'unique' => 'Ce :attribute existe déjà.',
    'uploaded' => 'Le téléchargement du fichier :attribute a échoué.',
    'url' => 'Le champ :attribute doit être une URL valide.',
    'uuid' => 'Le champ :attribute doit être un UUID valide.',

    /*
    |--------------------------------------------------------------------------
    | Custom Validation Language Lines
    |--------------------------------------------------------------------------
    |
    | Here you may specify custom validation messages for attributes using the
    | convention "attribute.rule" to name the lines. This makes it quick to
    | specify a specific custom language line for a given attribute rule.
    |
    */

    'custom' => [
        'attribute-name' => [
            'rule-name' => 'custom-message',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Validation Attributes
    |--------------------------------------------------------------------------
    |
    | The following language lines are used to swap our attribute placeholder
    | with something more reader friendly such as "E-Mail Address" instead
    | of "email". This simply helps us make our message more expressive.
    |
    */

    'attributes' => [
        'numero_compte' => 'numéro de compte',
        'nom_raison_sociale' => 'nom/raison sociale',
        'bp' => 'boîte postale',
        'ville' => 'ville',
        'pays' => 'pays',
        'adresse_geo_1' => 'adresse géographique 1',
        'adresse_geo_2' => 'adresse géographique 2',
        'telephone' => 'téléphone',
        'email' => 'email',
        'categorie' => 'catégorie',
        'n_contribuable' => 'numéro de contribuable',
        'type_tiers' => 'type de tiers',
        'date_creation' => 'date de création',
        'montant_facture' => 'montant facturé',
        'montant_paye' => 'montant payé',
        'credit' => 'crédit',
        'motif' => 'motif',
        'etablissement' => 'établissement',
        'service' => 'service',
        'nom_signataire' => 'nom du signataire',
    ],

];
