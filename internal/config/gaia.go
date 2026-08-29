package config

// Gaia is the Gaia-X participant description this node publishes.
//
// It is transcribed rather than interpreted: the shapes come from the Gaia-X
// Trust Framework, and config's only job is to carry them to whoever mints the
// credential. Validation belongs there, against the schema, not here.
type Gaia struct {
	LegalPerson LegalPerson `mapstructure:"legal_person"`
}

// LegalPerson is the organisation operating this node.
type LegalPerson struct {
	Name                string             `mapstructure:"name"`
	Description         string             `mapstructure:"description"`
	RegistrationNumber  RegistrationNumber `mapstructure:"registration_number"`
	LegalAddress        Address            `mapstructure:"legal_address"`
	HeadquartersAddress Address            `mapstructure:"headquarters_address"`
}

// RegistrationNumber identifies the organisation in a public registry.
type RegistrationNumber struct {
	// Kind is the registry the number belongs to, e.g. "VatId".
	Kind  string `mapstructure:"kind"`
	Value string `mapstructure:"value"`
	// CountryCode is the ISO 3166-1 alpha-2 code of the issuing country.
	CountryCode string `mapstructure:"country_code"`
	// SubdivisionCountryCode is the ISO 3166-2 code, where the registry is
	// regional rather than national.
	SubdivisionCountryCode string `mapstructure:"subdivision_country_code,omitempty"`
}

// Address is a postal address in Gaia-X vCard terms.
type Address struct {
	CountryCode   string `mapstructure:"country_code"`
	CountryName   string `mapstructure:"country_name"`
	Locality      string `mapstructure:"locality"`
	PostalCode    string `mapstructure:"postal_code"`
	StreetAddress string `mapstructure:"street_address"`
}
