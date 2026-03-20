package ioarulegroup

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string {
	return &s
}

func TestConvertIOARuleGroupsToIDs(t *testing.T) {
	tests := []struct {
		name     string
		groups   []*models.IoaRuleGroupsRuleGroupV1
		expected []types.String
	}{
		{
			name:     "empty slice",
			groups:   []*models.IoaRuleGroupsRuleGroupV1{},
			expected: []types.String{},
		},
		{
			name:     "nil slice",
			groups:   nil,
			expected: []types.String{},
		},
		{
			name: "nil entry",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				nil,
			},
			expected: []types.String{},
		},
		{
			name: "entry with nil ID",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: nil},
			},
			expected: []types.String{},
		},
		{
			name: "single valid entry",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
			},
			expected: []types.String{types.StringValue("id-1")},
		},
		{
			name: "multiple valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				{ID: strPtr("id-2")},
				{ID: strPtr("id-3")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
				types.StringValue("id-3"),
			},
		},
		{
			name: "mixed nil and valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				nil,
				{ID: nil},
				{ID: strPtr("id-2")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertIOARuleGroupsToIDs(tt.groups)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertIOARuleGroupToSet(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*models.IoaRuleGroupsRuleGroupV1
		expectedCount int
	}{
		{
			name:          "empty slice",
			groups:        []*models.IoaRuleGroupsRuleGroupV1{},
			expectedCount: 0,
		},
		{
			name: "valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				{ID: strPtr("id-2")},
			},
			expectedCount: 2,
		},
		{
			name: "skips nil entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				nil,
				{ID: strPtr("id-2")},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := ConvertIOARuleGroupToSet(t.Context(), tt.groups)
			assert.False(t, diags.HasError())
			assert.Len(t, result.Elements(), tt.expectedCount)
		})
	}
}

func TestConvertIOARuleGroupToList(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*models.IoaRuleGroupsRuleGroupV1
		expectedCount int
		expectedIDs   []string
	}{
		{
			name:          "empty slice",
			groups:        []*models.IoaRuleGroupsRuleGroupV1{},
			expectedCount: 0,
			expectedIDs:   []string{},
		},
		{
			name: "preserves order",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-b")},
				{ID: strPtr("id-a")},
			},
			expectedCount: 2,
			expectedIDs:   []string{"id-b", "id-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := ConvertIOARuleGroupToList(t.Context(), tt.groups)
			assert.False(t, diags.HasError())
			assert.Len(t, result.Elements(), tt.expectedCount)

			if tt.expectedCount > 0 {
				var ids []string
				result.ElementsAs(t.Context(), &ids, false)
				assert.Equal(t, tt.expectedIDs, ids)
			}
		})
	}
}

func TestIOARuleGroupResourceSchemaPlanModifiers(t *testing.T) {
	res := NewIOARuleGroupResource()

	var resp resource.SchemaResponse
	res.Schema(t.Context(), resource.SchemaRequest{}, &resp)
	require.False(t, resp.Diagnostics.HasError())

	modifiedByAttr, ok := resp.Schema.Attributes["modified_by"].(schema.StringAttribute)
	require.True(t, ok)
	require.Len(t, modifiedByAttr.PlanModifiers, 1)
	assert.IsType(t, stringplanmodifier.UseStateForUnknown(), modifiedByAttr.PlanModifiers[0])

	modifiedOnAttr, ok := resp.Schema.Attributes["modified_on"].(schema.StringAttribute)
	require.True(t, ok)
	require.Len(t, modifiedOnAttr.PlanModifiers, 1)
	assert.IsType(t, stringplanmodifier.UseStateForUnknown(), modifiedOnAttr.PlanModifiers[0])

	committedOnAttr, ok := resp.Schema.Attributes["committed_on"].(schema.StringAttribute)
	require.True(t, ok)
	require.Len(t, committedOnAttr.PlanModifiers, 1)
	assert.IsType(t, stringplanmodifier.UseStateForUnknown(), committedOnAttr.PlanModifiers[0])

	rulesAttr, ok := resp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	require.True(t, ok)

	ruleEnabledAttr, ok := rulesAttr.NestedObject.Attributes["enabled"].(schema.BoolAttribute)
	require.True(t, ok)
	require.Len(t, ruleEnabledAttr.PlanModifiers, 1)
	assert.IsType(t, boolplanmodifier.UseStateForUnknown(), ruleEnabledAttr.PlanModifiers[0])

	for _, fieldName := range excludableFieldNames {
		fieldAttr, ok := rulesAttr.NestedObject.Attributes[fieldName].(schema.SingleNestedAttribute)
		require.True(t, ok, fieldName)
		require.Len(t, fieldAttr.PlanModifiers, 1, fieldName)
		assert.IsType(t, objectplanmodifier.UseStateForUnknown(), fieldAttr.PlanModifiers[0], fieldName)

		includeAttr, ok := fieldAttr.Attributes["include"].(schema.StringAttribute)
		require.True(t, ok, fieldName)
		require.Len(t, includeAttr.PlanModifiers, 1, fieldName)
		assert.IsType(t, stringplanmodifier.UseStateForUnknown(), includeAttr.PlanModifiers[0], fieldName)
	}
}
