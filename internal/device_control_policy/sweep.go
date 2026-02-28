package devicecontrolpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_device_control_policy", sweepDeviceControlPolicies)
}

func sweepDeviceControlPolicies(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	filter := fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix)
	queryResp, err := client.DeviceControlPolicies.QueryCombinedDeviceControlPolicies(
		&device_control_policies.QueryCombinedDeviceControlPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Device Control Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error querying device control policies: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil {
		return sweepables, nil
	}

	for _, policy := range queryResp.Payload.Resources {
		if policy == nil || policy.ID == nil || policy.Name == nil {
			continue
		}

		if !strings.HasPrefix(*policy.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping device control policy %s (not a test resource)", *policy.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*policy.ID,
			*policy.Name,
			deleteDeviceControlPolicy,
		))
	}

	return sweepables, nil
}

func deleteDeviceControlPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) error {
	_, err := client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
		&device_control_policies.PerformDeviceControlPoliciesActionParams{
			Context:    ctx,
			ActionName: "disable",
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{id},
			},
		},
	)
	if err != nil && !sweep.ShouldIgnoreError(err) {
		return fmt.Errorf("error disabling device control policy %s: %w", id, err)
	}

	_, err = client.DeviceControlPolicies.DeleteDeviceControlPolicies(
		&device_control_policies.DeleteDeviceControlPoliciesParams{
			Context: ctx,
			Ids:     []string{id},
		},
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary || sweep.ShouldIgnoreError(err) {
			return nil
		}
		return fmt.Errorf("error deleting device control policy %s: %w", id, err)
	}

	return nil
}
