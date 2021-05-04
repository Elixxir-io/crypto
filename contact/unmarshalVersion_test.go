///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package contact

import (
	"encoding/base64"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

// Consistency test for unmarshal version "0".
func TestContact_unmarshalVer0_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact
	expectedContact := []string{
		"<xxc(0)JAAeAAIAr79ksZZ/jFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpAQhytEufu5cbAAAAAAAAAAAAAAAAAAAAOw==xxc>",
		"<xxc(0)JAD4A/gCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+6SdgMefxJXpATEMemGbQnZNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVVdBZy9ZZE4xdkFLMEhmVDVHU25oajlxZWI0TGxUblNPZ2VlZVM3MXY0MHpjdW9RKzZOWStqRS8rSE92cVZHMlByQlBkR3F3RXppNmloM3hWZWMraXg0NGJDNjg9LFVyb2hhZUdJR0ZwZUs3UXpqeHNUenJudkQ0RWxiVnhMKy9iNE1FQ2lINFFEYXpTMklYMmtzdGdmYUFLRWNISEJ4NTVhaTNDM0NXbHQwc3VFcGNGNG5Qd1hKSXc9PTs=xxc>",
		"<xxc(0)AABmANQD8kFE8/1HiUkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVUpvS09Ld1U0bGszOXg1Nk5VME56Wmh6OVp0ZFA3QjRiaVVrYXR5TnVTM1VoWXBEUEsrdEN3OG9uTW9WZzhhckFaODZtNkw5RzFLc3JSb0JBTEYreWdnNklYVEpnOGQ2WGdvUFVvSm8yK1d3Z2xCZEc0KzFOcGthcHJvdFBwN1Q4T2lDNitocDE3VEo2aHJpd3c1cnh6OUt6dFJJWjZubFRPcjlFalN4SG5USmdkVE9RV1JUSXpCenduYU9lRHBLZEFrcTh2TEZwT1h1M05PZnZDbTRCOFlWTjYxL2tKUDczckNFSWtmV1g7xxc>",
		"<xxc(0)JAAAANQDXMCYoCcs5+sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpAQfDMrfm2pchVVhpa3FvcmlxSEJzajRSeEk3UmRUbldoZmR2S25tTHhrM2c1ZHNvWkxLdFBDYk9ZNEkwSjJXaFBXbHVVdDkyRDJ3MFplS2FEY3BHckRvTlZ3RXp2Q0ZYSDE5VXBrTVFWUlA5aENteGxLNGJxZktvT0dybkt6Wmgvb0xDckdUYjlHRlJnazRqQlRFbU44bWNLNGZXM3czVjd5ZzJjWkJ5MW5MMkg2b0w2RzlGZVNIc044RGtZTThOY0QwSDNGOVdZYVJRRXpRSnB4SzJwbXE5ZTZaU0pNb21sNDJhWE9ZdjZ4R29PUEZtST07xxc>",
		"<xxc(0)JADWAQIBmRapMxk8GJwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpAVYZCbc7GF5YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7xxc>",
		"<xxc(0)AAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOw==xxc>",
		"<xxc(0)JACGA8QDKkZsyvJsulEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpATXNRV0vFojtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVTRTL1Y0WnFGdTRkRGUwRURNRm83T0d4OU50a3RJbFNaWUtjVThxZ3A0Y0lDRm5PL01NVUxaNTFRVm9sVnljR1lDSjJWOWdPWDBxOWZqOGtSQytPcDRTWHBSSVNYbHdqV3FuejhZcDZOa1VmUEwxKzJvRldScTRhSE9oNnRCYVNtWngxcFVWeURuZGl2T2pyWGRBTEYvVHFEb0VZSXFZa3pBQ0ZpM1V3ZjlWUi9WMUlESHlFaDRVRUlxbHBYUld5dWtjRnpLYTFhem1IcTZiWlMzek1BdE1LcldDZDIyRnRvOw==xxc>",
		"<xxc(0)JAD0AQIBkJxljeRro48AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpAXPkxwFBc+E/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7xxc>",
		"<xxc(0)JABuALAGF2j1Bc9kkS4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpARF2XdaknsjSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFV5akxWdzg4SWFqN0QyTE4zQUJMOUo2UzJXd0t1aFNWdmMyN2VQazNZVnlDVmRhU0kxWFFOTDNKcFdsY052eVpIOHBYaU01WHUycy8yTnVHd3p5RGVhaEQvbVVQdHltK1d2MDNhOEF1ZFQ4MXF5OXV6OWpHVVVEV0dxS1pZcm1DMTdsT2F0YTBaOHJvajNLWm4zNlpWRTB4WlNpeUFhOStrNTFia1dMU0xya2tOQkM0SG8xWHBiUHVKekt2eWdaMTVUWjRTZ3YwS2NsVHhzNVQyNnJ4bXBraTYzOXRIMDFDS2FUZ0xwZz09LFVyWWFYcHpSanpTZ0c1cTd1K1N0ZW0vL2tEcFJtbVEranJzRWVTbnkycnJzWHQvN1NsUlBUSHRUL0hSYm0xWmxXR1ZGZlgxT0hhUUR0RDNyUjhqaTdNMFFKNDhGa2xYT2xiME9vNGRJVGNrYjhwc1l6Sk5RL2crd05UUy9XVUcvZjd1SWVKREk5Z09mTGhGOUQwaU1pbXFRaEZFb24yN2ZFUU1ISG1QbWlUUT09Ow==xxc>",
		"<xxc(0)JACGA9AFqO/kc3tbpXkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6SdgMefxJXpAR1P1DZOQ0GyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVUxJWHhMQ1NJS3FaUmxVaVF2TnpQWnEwOWM2amhxNStEaDMwbU83c245YnhKZTlaVVIwM0xoaXEwM1dpYm9FME5ybWlnZzlhbDZIVEVIT1N1ZHAzZHRpSEJaREk1dlRlS0xwR3ByT0ozOHNDTmNVdkoyZVlzQldMS0tXNFNwM1lYUk4yNEk2Z3ZHYnA5Q2xKTFZKSzc5eXJEVHZ5NUNsN2ZiYndobjc4dzdQSmZwbWJKSkdzSUhWMHNWNDd2QUFpd2pXR2dsMlFFOUM2b0traHordzFraDNkOXBrY0d0MGhYcFo4ZEtuODJGNk84MVZxVm45R1NCTUxqdjZ6ZzVnTUxmQUJwdVh4cERKZzB3aWdwdXB2VS82bXZXQmx2ZDE0dzg4azdTZXd2SG9vMyxVNUVpSWQvOTZhN3lzNCs2Z0c5ZFpRQTJIdVlDelU4RVZ5OEZpcDNqZG5xQkNOWjFNSVA0aGlrWT07xxc>",
	}

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Int63n(255)),
			Facts:          fact.FactList{},
		})

		// Add facts to contact
		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(255))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Set some fields to nil for certain contact
		switch i {
		case 1:
			contacts[i].ID = nil
		case 2:
			contacts[i].DhPubKey = nil
		case 3:
			contacts[i].OwnershipProof = nil
		case 4:
			contacts[i].Facts = nil
		case 5:
			contacts[i] = Contact{}
		}
	}

	for i, c := range contacts {
		expected, err := Unmarshal([]byte(expectedContact[i]))
		if err != nil {
			t.Errorf("Unmarshal() failed to unmarshal contact %d: %+v", i, err)
		}
		if !Equal(expected, c) {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expected, c)
		}
	}
}

// Consistency test for unmarshal version "1".
func TestContact_unmarshalVer1_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact
	expectedContact := []string{
		"<xxc(1)r79ksZZ/jFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QhytEufu5cbHgAAAAAAAAAAAAAAAAAAAAACADtKskOgLDXmWNjAd/JKRAsjxxc>",
		"<xxc(1)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAB7Ugdw/BAr6TEMemGbQnZN+AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4AlVXQWcvWWROMXZBSzBIZlQ1R1NuaGo5cWViNExsVG5TT2dlZWVTNzF2NDB6Y3VvUSs2TlkrakUvK0hPdnFWRzJQckJQZEdxd0V6aTZpaDN4VmVjK2l4NDRiQzY4PSxVcm9oYWVHSUdGcGVLN1F6anhzVHpybnZENEVsYlZ4TCsvYjRNRUNpSDRRRGF6UzJJWDJrc3RnZmFBS0VjSEhCeDU1YWkzQzNDV2x0MHN1RXBjRjRuUHdYSkl3PT07Ja1wdi00RzAZ0NXoztr/2g==xxc>",
		"<xxc(1)8kFE8/1HiUkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAABmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANQDVUpvS09Ld1U0bGszOXg1Nk5VME56Wmh6OVp0ZFA3QjRiaVVrYXR5TnVTM1VoWXBEUEsrdEN3OG9uTW9WZzhhckFaODZtNkw5RzFLc3JSb0JBTEYreWdnNklYVEpnOGQ2WGdvUFVvSm8yK1d3Z2xCZEc0KzFOcGthcHJvdFBwN1Q4T2lDNitocDE3VEo2aHJpd3c1cnh6OUt6dFJJWjZubFRPcjlFalN4SG5USmdkVE9RV1JUSXpCenduYU9lRHBLZEFrcTh2TEZwT1h1M05PZnZDbTRCOFlWTjYxL2tKUDczckNFSWtmV1g76dVYCnuwy9IKOnBnsdZc6w==xxc>",
		"<xxc(1)XMCYoCcs5+sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QfDMrfm2pchAADUA1VYaWtxb3JpcUhCc2o0UnhJN1JkVG5XaGZkdktubUx4azNnNWRzb1pMS3RQQ2JPWTRJMEoyV2hQV2x1VXQ5MkQydzBaZUthRGNwR3JEb05Wd0V6dkNGWEgxOVVwa01RVlJQOWhDbXhsSzRicWZLb09Hcm5LelpoL29MQ3JHVGI5R0ZSZ2s0akJURW1OOG1jSzRmVzN3M1Y3eWcyY1pCeTFuTDJINm9MNkc5RmVTSHNOOERrWU04TmNEMEgzRjlXWWFSUUV6UUpweEsycG1xOWU2WlNKTW9tbDQyYVhPWXY2eEdvT1BGbUk9OyCqN9QrkEfTKI6BZZv9Oic=xxc>",
		"<xxc(1)mRapMxk8GJwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6VYZCbc7GF5Y1gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAO/bRhXoH8E2ROTuF9oTytxI=xxc>",
		"<xxc(1)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAO57st9tZ0WyAQXxy0eH0+/E=xxc>",
		"<xxc(1)KkZsyvJsulEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6TXNRV0vFojthgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEA1U0Uy9WNFpxRnU0ZERlMEVETUZvN09HeDlOdGt0SWxTWllLY1U4cWdwNGNJQ0ZuTy9NTVVMWjUxUVZvbFZ5Y0dZQ0oyVjlnT1gwcTlmajhrUkMrT3A0U1hwUklTWGx3aldxbno4WXA2TmtVZlBMMSsyb0ZXUnE0YUhPaDZ0QmFTbVp4MXBVVnlEbmRpdk9qclhkQUxGL1RxRG9FWUlxWWt6QUNGaTNVd2Y5VlIvVjFJREh5RWg0VUVJcWxwWFJXeXVrY0Z6S2ExYXptSHE2YlpTM3pNQXRNS3JXQ2QyMkZ0bztlb7a9jJqr6P8I1p1aMnsFxxc>",
		"<xxc(1)kJxljeRro48AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6XPkxwFBc+E/9AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAO/Jh9skYcXF0cUXAj4bIr70=xxc>",
		"<xxc(1)F2j1Bc9kkS4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6RF2XdaknsjSbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAZVeWpMVnc4OElhajdEMkxOM0FCTDlKNlMyV3dLdWhTVnZjMjdlUGszWVZ5Q1ZkYVNJMVhRTkwzSnBXbGNOdnlaSDhwWGlNNVh1MnMvMk51R3d6eURlYWhEL21VUHR5bStXdjAzYThBdWRUODFxeTl1ejlqR1VVRFdHcUtaWXJtQzE3bE9hdGEwWjhyb2ozS1puMzZaVkUweFpTaXlBYTkrazUxYmtXTFNMcmtrTkJDNEhvMVhwYlB1SnpLdnlnWjE1VFo0U2d2MEtjbFR4czVUMjZyeG1wa2k2Mzl0SDAxQ0thVGdMcGc9PSxVcllhWHB6Ump6U2dHNXE3dStTdGVtLy9rRHBSbW1RK2pyc0VlU255MnJyc1h0LzdTbFJQVEh0VC9IUmJtMVpsV0dWRmZYMU9IYVFEdEQzclI4amk3TTBRSjQ4RmtsWE9sYjBPbzRkSVRja2I4cHNZekpOUS9nK3dOVFMvV1VHL2Y3dUllSkRJOWdPZkxoRjlEMGlNaW1xUWhGRW9uMjdmRVFNSEhtUG1pVFE9PTtlQRWDJZjipYksXPYbtahnxxc>",
		"<xxc(1)qO/kc3tbpXkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6R1P1DZOQ0GyhgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQBVVMSVh4TENTSUtxWlJsVWlRdk56UFpxMDljNmpocTUrRGgzMG1PN3NuOWJ4SmU5WlVSMDNMaGlxMDNXaWJvRTBOcm1pZ2c5YWw2SFRFSE9TdWRwM2R0aUhCWkRJNXZUZUtMcEdwck9KMzhzQ05jVXZKMmVZc0JXTEtLVzRTcDNZWFJOMjRJNmd2R2JwOUNsSkxWSks3OXlyRFR2eTVDbDdmYmJ3aG43OHc3UEpmcG1iSkpHc0lIVjBzVjQ3dkFBaXdqV0dnbDJRRTlDNm9La2h6K3cxa2gzZDlwa2NHdDBoWHBaOGRLbjgyRjZPODFWcVZuOUdTQk1ManY2emc1Z01MZkFCcHVYeHBESmcwd2lncHVwdlUvNm12V0JsdmQxNHc4OGs3U2V3dkhvbzMsVTVFaUlkLzk2YTd5czQrNmdHOWRaUUEySHVZQ3pVOEVWeThGaXAzamRucUJDTloxTUlQNGhpa1k9O5zoEGNsENLXL8Q+yPNthsQ=xxc>",
	}

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Int63n(255)),
			Facts:          fact.FactList{},
		})

		// Add facts to contact
		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(255))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Set some fields to nil for certain contact
		switch i {
		case 1:
			contacts[i].ID = nil
		case 2:
			contacts[i].DhPubKey = nil
		case 3:
			contacts[i].OwnershipProof = nil
		case 4:
			contacts[i].Facts = nil
		case 5:
			contacts[i] = Contact{}
		}
	}

	for i, c := range contacts {
		expected, err := Unmarshal([]byte(expectedContact[i]))
		if err != nil {
			t.Errorf("Unmarshal() failed to unmarshal contact %d: %+v", i, err)
		}
		if !Equal(expected, c) {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expected, c)
		}
	}
}