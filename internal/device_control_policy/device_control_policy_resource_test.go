package devicecontrolpolicy_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDeviceControlPolicyResource_basicLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC_DEVICE_CONTROL_POLICY") != "true" {
		t.Skip("Skipping Device Control Policy acceptance test. Set TF_ACC_DEVICE_CONTROL_POLICY=true to run this test.")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_device_control_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDeviceControlPolicyConfigBasic(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Terraform device control policy"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "settings.0.enforcement_mode", "MONITOR_ENFORCE"),
					resource.TestCheckResourceAttr(resourceName, "settings.0.end_user_notification", "NOTIFY_USER"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccDeviceControlPolicyConfigUpdated(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated Terraform device control policy"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "settings.0.classes.0.exceptions.0.combined_id", "1234_5678_SERIAL-B"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func testAccDeviceControlPolicyConfigBasic(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name          = %[1]q
  description   = "Terraform device control policy"
  platform_name = "Windows"
  enabled       = false

  settings = {
    enforcement_mode      = "MONITOR_ENFORCE"
    end_user_notification = "NOTIFY_USER"

    classes = [
      {
        id     = "MASS_STORAGE"
        action = "BLOCK_ALL"

        exceptions = [
          {
            combined_id = "1234_5678_SERIAL-A"
            action      = "FULL_ACCESS"
            description = "Allow approved USB A"
          }
        ]
      }
    ]
  }
}
`, name)
}

func testAccDeviceControlPolicyConfigUpdated(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name          = "%[1]s-updated"
  description   = "Updated Terraform device control policy"
  platform_name = "Windows"
  enabled       = true

  settings = {
    enforcement_mode      = "MONITOR_ENFORCE"
    end_user_notification = "NOTIFY_USER"

    classes = [
      {
        id     = "MASS_STORAGE"
        action = "BLOCK_ALL"

        exceptions = [
          {
            combined_id = "1234_5678_SERIAL-B"
            action      = "FULL_ACCESS"
            description = "Allow approved USB B"
          }
        ]
      }
    ]
  }
}
`, name)
}
