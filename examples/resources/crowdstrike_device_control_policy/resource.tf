resource "crowdstrike_device_control_policy" "example" {
  name          = "example-device-control-policy"
  description   = "Manage USB mass storage access"
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
            combined_id = "1234_5678_SERIAL123"
            action      = "FULL_ACCESS"
            description = "Approved USB device"
          }
        ]
      },
      {
        id     = "WIRELESS"
        action = "BLOCK_ALL"
      }
    ]

    custom_notifications = {
      blocked_notification = {
        use_custom     = true
        custom_message = "USB access is blocked by policy"
      }
    }
  }
}
