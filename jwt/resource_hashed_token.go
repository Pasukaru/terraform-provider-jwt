package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	jwtgen "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceHashedToken() *schema.Resource {
	return &schema.Resource{
		Create: createHashedJWT,
		Delete: deleteHashedJWT,
		Read:   readHashedJWT,

		Description: `
Provides a way to sign a JSON Web Token using a secret (with the HMAC algorithm). More information about JWT [here](https://jwt.io/introduction/).
`,

		Schema: map[string]*schema.Schema{
			"algorithm": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HS512",
				Description:  "Signing algorithm to use. Defaults to `HS512`. Supported algorithms are `HS256`, `HS384`, `HS512`.",
				ValidateFunc: validateHashingAlgorithm,
				ForceNew:     true,
			},
			"secret_base64": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "HMAC secret as base64 string to sign the JWT with.",
				ForceNew:    true,
				Sensitive:   true,
			},
			"claims_json": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The token's claims, as a JSON document.",
				ForceNew:    true,
			},
			"token": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The JWT token, as a string.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func createHashedJWT(d *schema.ResourceData, meta interface{}) (err error) {
	alg := d.Get("algorithm").(string)
	signer := jwtgen.GetSigningMethod(alg)

	claims := d.Get("claims_json").(string)

	jsonClaims := make(map[string]interface{})
	err = json.Unmarshal([]byte(claims), &jsonClaims)
	if err != nil {
		return err
	}

	token := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(jsonClaims))

	secretBase64 := d.Get("secret_base64").(string)
	secret, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		return err
	}

	hashedToken, err := token.SignedString(secret)
	if err != nil {
		return err
	}
	compactClaims, _ := json.Marshal(token.Claims)
	d.SetId(string(compactClaims))
	err = d.Set("token", hashedToken)
	if err != nil {
		return err
	}
	return
}

func deleteHashedJWT(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func readHashedJWT(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func validateHashingAlgorithm(iAlg interface{}, k string) (warnings []string, errs []error) {
	alg, ok := iAlg.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string.", k))
		return
	}
	method := jwtgen.GetSigningMethod(alg)
	if method == nil {
		errs = append(errs, fmt.Errorf("%s is not a supported signing algorithm. Choices are HS256, HS384, HS512.", alg))
		return
	}
	if _, isHMAC := method.(*jwtgen.SigningMethodHMAC); !isHMAC {
		errs = append(errs, fmt.Errorf("For RSA/ECDSA signing, please use the jwt_signed_token resource."))
	}
	return
}
