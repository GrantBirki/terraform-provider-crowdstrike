package devicecontrolpolicy

import (
	"slices"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestMapAPIActionToTerraform(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "full block", input: "FULL_BLOCK", expected: "BLOCK_ALL"},
		{name: "read only", input: "READ_ONLY", expected: "BLOCK_WRITE_EXECUTE"},
		{name: "pass through", input: "FULL_ACCESS", expected: "FULL_ACCESS"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mapAPIActionToTerraform(tc.input); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestExpandSettingsTracksExceptionIDsAndDeletesRemovedOnes(t *testing.T) {
	t.Parallel()

	policyID := "policy-id"
	classID := "MASS_STORAGE"
	existingIDToKeep := "exception-keep"
	existingIDToDelete := "exception-delete"

	model := deviceControlPolicyResourceModel{
		settings: deviceControlSettingsModel{
			EnforcementMode:     types.StringValue("MONITOR_ENFORCE"),
			EndUserNotification: types.StringValue("NOTIFY_USER"),
			EnhancedFileMeta:    types.BoolValue(false),
			classes: []deviceControlClassModel{
				{
					ID:     types.StringValue(classID),
					Action: types.StringValue("BLOCK_ALL"),
					exceptions: []deviceControlExceptionModel{
						{
							CombinedID: types.StringValue("1234_5678_SERIAL-A"),
							Action:     types.StringValue("FULL_ACCESS"),
						},
						{
							CombinedID: types.StringValue("FFFF_EEEE_SERIAL-C"),
							Action:     types.StringValue("FULL_ACCESS"),
						},
					},
				},
			},
		},
	}

	currentPolicy := &models.DeviceControlPolicyV1{
		ID: &policyID,
		Settings: &models.DeviceControlSettingsRespV1{
			Classes: []*models.DeviceControlUSBClassExceptionsResponse{
				{
					ID: &classID,
					Exceptions: []*models.DeviceControlExceptionRespV1{
						{
							ID:         &existingIDToKeep,
							CombinedID: "1234_5678_SERIAL-A",
						},
						{
							ID:         &existingIDToDelete,
							CombinedID: "9999_8888_SERIAL-B",
						},
					},
				},
			},
		},
	}

	settings, diags := model.expandSettings(t.Context(), currentPolicy)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if settings == nil {
		t.Fatal("expected settings to be created")
	}

	if len(settings.Classes) != 1 {
		t.Fatalf("expected 1 class, got %d", len(settings.Classes))
	}

	if len(settings.Classes[0].Exceptions) != 2 {
		t.Fatalf("expected 2 exceptions, got %d", len(settings.Classes[0].Exceptions))
	}

	if settings.Classes[0].Exceptions[0].ID != existingIDToKeep {
		t.Fatalf("expected first exception ID %q, got %q", existingIDToKeep, settings.Classes[0].Exceptions[0].ID)
	}

	if settings.Classes[0].Exceptions[1].ID != "" {
		t.Fatalf("expected new exception to not have an ID, got %q", settings.Classes[0].Exceptions[1].ID)
	}

	if !slices.Equal(settings.DeleteExceptions, []string{existingIDToDelete}) {
		t.Fatalf("expected delete exceptions [%s], got %v", existingIDToDelete, settings.DeleteExceptions)
	}
}
