package devicecontrolpolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &deviceControlPolicyResource{}
	_ resource.ResourceWithConfigure      = &deviceControlPolicyResource{}
	_ resource.ResourceWithImportState    = &deviceControlPolicyResource{}
	_ resource.ResourceWithValidateConfig = &deviceControlPolicyResource{}
)

func NewDeviceControlPolicyResource() resource.Resource {
	return &deviceControlPolicyResource{}
}

type deviceControlPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

type deviceControlPolicyResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Platform    types.String `tfsdk:"platform_name"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	CloneID     types.String `tfsdk:"clone_id"`
	HostGroups  types.Set    `tfsdk:"host_groups"`
	Settings    types.Object `tfsdk:"settings"`
	LastUpdated types.String `tfsdk:"last_updated"`

	settings deviceControlSettingsModel `tfsdk:"-"`
}

type deviceControlSettingsModel struct {
	EnforcementMode     types.String `tfsdk:"enforcement_mode"`
	EndUserNotification types.String `tfsdk:"end_user_notification"`
	EnhancedFileMeta    types.Bool   `tfsdk:"enhanced_file_metadata"`
	Classes             types.List   `tfsdk:"classes"`
	CustomNotifications types.Object `tfsdk:"custom_notifications"`

	classes             []deviceControlClassModel         `tfsdk:"-"`
	customNotifications *deviceControlCustomNotifications `tfsdk:"-"`
}

type deviceControlClassModel struct {
	ID         types.String `tfsdk:"id"`
	Action     types.String `tfsdk:"action"`
	Exceptions types.List   `tfsdk:"exceptions"`

	exceptions []deviceControlExceptionModel `tfsdk:"-"`
}

type deviceControlExceptionModel struct {
	ID               types.String `tfsdk:"id"`
	CombinedID       types.String `tfsdk:"combined_id"`
	VendorID         types.String `tfsdk:"vendor_id"`
	VendorIDDecimal  types.String `tfsdk:"vendor_id_decimal"`
	VendorName       types.String `tfsdk:"vendor_name"`
	ProductID        types.String `tfsdk:"product_id"`
	ProductIDDecimal types.String `tfsdk:"product_id_decimal"`
	ProductName      types.String `tfsdk:"product_name"`
	SerialNumber     types.String `tfsdk:"serial_number"`
	Description      types.String `tfsdk:"description"`
	Action           types.String `tfsdk:"action"`
	ExpirationTime   types.String `tfsdk:"expiration_time"`
	UseWildcard      types.Bool   `tfsdk:"use_wildcard"`
}

type deviceControlCustomNotifications struct {
	BlockedNotification    types.Object `tfsdk:"blocked_notification"`
	RestrictedNotification types.Object `tfsdk:"restricted_notification"`

	blockedNotification    *deviceControlCustomNotification `tfsdk:"-"`
	restrictedNotification *deviceControlCustomNotification `tfsdk:"-"`
}

type deviceControlCustomNotification struct {
	UseCustom     types.Bool   `tfsdk:"use_custom"`
	CustomMessage types.String `tfsdk:"custom_message"`
}

func deviceControlSettingsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enforcement_mode":       types.StringType,
		"end_user_notification":  types.StringType,
		"enhanced_file_metadata": types.BoolType,
		"classes": types.ListType{
			ElemType: types.ObjectType{AttrTypes: deviceControlClassAttrTypes()},
		},
		"custom_notifications": types.ObjectType{AttrTypes: deviceControlCustomNotificationsAttrTypes()},
	}
}

func deviceControlClassAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":     types.StringType,
		"action": types.StringType,
		"exceptions": types.ListType{
			ElemType: types.ObjectType{AttrTypes: deviceControlExceptionAttrTypes()},
		},
	}
}

func deviceControlExceptionAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                 types.StringType,
		"combined_id":        types.StringType,
		"vendor_id":          types.StringType,
		"vendor_id_decimal":  types.StringType,
		"vendor_name":        types.StringType,
		"product_id":         types.StringType,
		"product_id_decimal": types.StringType,
		"product_name":       types.StringType,
		"serial_number":      types.StringType,
		"description":        types.StringType,
		"action":             types.StringType,
		"expiration_time":    types.StringType,
		"use_wildcard":       types.BoolType,
	}
}

func deviceControlCustomNotificationsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"blocked_notification":    types.ObjectType{AttrTypes: deviceControlCustomNotificationAttrTypes()},
		"restricted_notification": types.ObjectType{AttrTypes: deviceControlCustomNotificationAttrTypes()},
	}
}

func deviceControlCustomNotificationAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"use_custom":     types.BoolType,
		"custom_message": types.StringType,
	}
}

func (m *deviceControlPolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	if !utils.IsKnown(m.Settings) {
		return diags
	}

	diags.Append(m.Settings.As(ctx, &m.settings, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return diags
	}

	diags.Append(m.settings.extract(ctx)...)
	return diags
}

func (m *deviceControlSettingsModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	m.classes = nil
	m.customNotifications = nil

	if utils.IsKnown(m.Classes) {
		diags.Append(m.Classes.ElementsAs(ctx, &m.classes, false)...)
		if diags.HasError() {
			return diags
		}

		for i := range m.classes {
			diags.Append(m.classes[i].extract(ctx)...)
			if diags.HasError() {
				return diags
			}
		}
	}

	if utils.IsKnown(m.CustomNotifications) {
		var custom deviceControlCustomNotifications
		diags.Append(m.CustomNotifications.As(ctx, &custom, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return diags
		}
		diags.Append(custom.extract(ctx)...)
		if diags.HasError() {
			return diags
		}
		m.customNotifications = &custom
	}

	return diags
}

func (m *deviceControlClassModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	m.exceptions = nil
	if !utils.IsKnown(m.Exceptions) {
		return diags
	}

	diags.Append(m.Exceptions.ElementsAs(ctx, &m.exceptions, false)...)
	return diags
}

func (m *deviceControlCustomNotifications) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	m.blockedNotification = nil
	m.restrictedNotification = nil

	if utils.IsKnown(m.BlockedNotification) {
		var blocked deviceControlCustomNotification
		diags.Append(m.BlockedNotification.As(ctx, &blocked, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return diags
		}
		m.blockedNotification = &blocked
	}

	if utils.IsKnown(m.RestrictedNotification) {
		var restricted deviceControlCustomNotification
		diags.Append(m.RestrictedNotification.As(ctx, &restricted, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return diags
		}
		m.restrictedNotification = &restricted
	}

	return diags
}

func (m *deviceControlPolicyResourceModel) wrap(
	ctx context.Context,
	policy *models.DeviceControlPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(policy.ID)
	m.Name = flex.StringPointerToFramework(policy.Name)
	m.Description = utils.PlanAwareStringValue(m.Description, policy.Description)
	m.Platform = flex.StringPointerToFramework(policy.PlatformName)
	m.Enabled = types.BoolPointerValue(policy.Enabled)

	hostGroupsSet, hostGroupsDiags := flex.FlattenHostGroupsToSet(ctx, policy.Groups)
	diags.Append(hostGroupsDiags...)
	if diags.HasError() {
		return diags
	}

	// Keep host_groups null when unset and API has no groups.
	if !m.HostGroups.IsNull() || len(hostGroupsSet.Elements()) != 0 {
		m.HostGroups = hostGroupsSet
	}

	diags.Append(m.wrapSettings(ctx, policy.Settings)...)
	return diags
}

func (m *deviceControlPolicyResourceModel) wrapSettings(
	ctx context.Context,
	apiSettings *models.DeviceControlSettingsRespV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if apiSettings == nil {
		m.Settings = types.ObjectNull(deviceControlSettingsAttrTypes())
		m.settings = deviceControlSettingsModel{}
		return diags
	}

	existingClassesByID := make(map[string]deviceControlClassModel, len(m.settings.classes))
	for _, existingClass := range m.settings.classes {
		if utils.IsKnown(existingClass.ID) {
			existingClassesByID[existingClass.ID.ValueString()] = existingClass
		}
	}

	settingsModel := deviceControlSettingsModel{
		EnforcementMode:     types.StringValue(mapEnforcementModeToTerraform(m.settings.EnforcementMode, apiSettings.EnforcementMode)),
		EndUserNotification: flex.StringPointerToFramework(apiSettings.EndUserNotification),
		EnhancedFileMeta:    types.BoolPointerValue(apiSettings.EnhancedFileMetadata),
		Classes:             types.ListNull(types.ObjectType{AttrTypes: deviceControlClassAttrTypes()}),
		CustomNotifications: types.ObjectNull(deviceControlCustomNotificationsAttrTypes()),
	}

	classModels := make([]deviceControlClassModel, 0, len(apiSettings.Classes))
	for _, apiClass := range apiSettings.Classes {
		if apiClass == nil {
			continue
		}

		classID := flex.StringPointerToFramework(apiClass.ID)
		classModel := deviceControlClassModel{
			ID:         classID,
			Action:     types.StringValue(mapAPIActionToTerraform(pointerString(apiClass.Action))),
			Exceptions: types.ListNull(types.ObjectType{AttrTypes: deviceControlExceptionAttrTypes()}),
		}

		existingClass, hasExistingClass := existingClassesByID[classID.ValueString()]
		existingExceptionsByID := map[string]deviceControlExceptionModel{}
		if hasExistingClass {
			for _, existingException := range existingClass.exceptions {
				if utils.IsKnown(existingException.ID) {
					existingExceptionsByID[existingException.ID.ValueString()] = existingException
				}
			}
		}

		exceptionModels := make([]deviceControlExceptionModel, 0, len(apiClass.Exceptions))
		for _, apiException := range apiClass.Exceptions {
			if apiException == nil {
				continue
			}

			exceptionModel := deviceControlExceptionModel{
				ID:               flex.StringPointerToFramework(apiException.ID),
				CombinedID:       flex.StringValueToFramework(apiException.CombinedID),
				VendorID:         flex.StringValueToFramework(apiException.VendorID),
				VendorIDDecimal:  flex.StringValueToFramework(apiException.VendorIDDecimal),
				VendorName:       flex.StringValueToFramework(apiException.VendorName),
				ProductID:        flex.StringValueToFramework(apiException.ProductID),
				ProductIDDecimal: flex.StringValueToFramework(apiException.ProductIDDecimal),
				ProductName:      flex.StringValueToFramework(apiException.ProductName),
				SerialNumber:     flex.StringValueToFramework(apiException.SerialNumber),
				Description:      flex.StringValueToFramework(apiException.Description),
				Action:           flex.StringValueToFramework(mapAPIActionToTerraform(apiException.Action)),
				UseWildcard:      types.BoolValue(false),
				ExpirationTime:   types.StringNull(),
			}

			if existingException, ok := existingExceptionsByID[exceptionModel.ID.ValueString()]; ok {
				exceptionModel.CombinedID = utils.SetStringFromAPIIfNotEmpty(existingException.CombinedID, apiException.CombinedID)
				exceptionModel.VendorID = utils.SetStringFromAPIIfNotEmpty(existingException.VendorID, apiException.VendorID)
				exceptionModel.VendorIDDecimal = utils.SetStringFromAPIIfNotEmpty(existingException.VendorIDDecimal, apiException.VendorIDDecimal)
				exceptionModel.VendorName = utils.SetStringFromAPIIfNotEmpty(existingException.VendorName, apiException.VendorName)
				exceptionModel.ProductID = utils.SetStringFromAPIIfNotEmpty(existingException.ProductID, apiException.ProductID)
				exceptionModel.ProductIDDecimal = utils.SetStringFromAPIIfNotEmpty(existingException.ProductIDDecimal, apiException.ProductIDDecimal)
				exceptionModel.ProductName = utils.SetStringFromAPIIfNotEmpty(existingException.ProductName, apiException.ProductName)
				exceptionModel.SerialNumber = utils.SetStringFromAPIIfNotEmpty(existingException.SerialNumber, apiException.SerialNumber)
				exceptionModel.Description = utils.SetStringFromAPIIfNotEmpty(existingException.Description, apiException.Description)
				exceptionModel.Action = utils.SetStringFromAPIIfNotEmpty(existingException.Action, mapAPIActionToTerraform(apiException.Action))
				exceptionModel.UseWildcard = existingException.UseWildcard
			}

			if !apiException.ExpirationTime.IsZero() {
				exceptionModel.ExpirationTime = types.StringValue(apiException.ExpirationTime.String())
			} else if existingException, ok := existingExceptionsByID[exceptionModel.ID.ValueString()]; ok {
				exceptionModel.ExpirationTime = utils.SetStringFromAPIIfNotEmpty(existingException.ExpirationTime, "")
			}

			if strings.EqualFold(apiException.MatchMethod, "BLOB") {
				exceptionModel.UseWildcard = types.BoolValue(true)
			}

			exceptionModels = append(exceptionModels, exceptionModel)
		}

		if len(exceptionModels) > 0 || (hasExistingClass && !existingClass.Exceptions.IsNull()) {
			exceptionsList, exceptionsDiags := types.ListValueFrom(
				ctx,
				types.ObjectType{AttrTypes: deviceControlExceptionAttrTypes()},
				exceptionModels,
			)
			diags.Append(exceptionsDiags...)
			if diags.HasError() {
				return diags
			}
			classModel.Exceptions = exceptionsList
		}

		classModel.exceptions = exceptionModels
		classModels = append(classModels, classModel)
	}

	classesList, classListDiags := types.ListValueFrom(
		ctx,
		types.ObjectType{AttrTypes: deviceControlClassAttrTypes()},
		classModels,
	)
	diags.Append(classListDiags...)
	if diags.HasError() {
		return diags
	}
	settingsModel.Classes = classesList
	settingsModel.classes = classModels

	customObject, customModel, customDiags := flattenCustomNotifications(
		ctx,
		m.settings.customNotifications,
		apiSettings.CustomNotifications,
	)
	diags.Append(customDiags...)
	if diags.HasError() {
		return diags
	}
	settingsModel.CustomNotifications = customObject
	settingsModel.customNotifications = customModel

	settingsObject, settingsDiags := types.ObjectValueFrom(ctx, deviceControlSettingsAttrTypes(), settingsModel)
	diags.Append(settingsDiags...)
	if diags.HasError() {
		return diags
	}

	m.settings = settingsModel
	m.Settings = settingsObject

	return diags
}

func flattenCustomNotifications(
	ctx context.Context,
	current *deviceControlCustomNotifications,
	api *models.DeviceControlUSBCustomNotifications,
) (types.Object, *deviceControlCustomNotifications, diag.Diagnostics) {
	var diags diag.Diagnostics

	if api == nil {
		return types.ObjectNull(deviceControlCustomNotificationsAttrTypes()), nil, diags
	}

	model := deviceControlCustomNotifications{
		BlockedNotification:    types.ObjectNull(deviceControlCustomNotificationAttrTypes()),
		RestrictedNotification: types.ObjectNull(deviceControlCustomNotificationAttrTypes()),
	}

	var blockedCurrent *deviceControlCustomNotification
	if current != nil {
		blockedCurrent = current.blockedNotification
	}
	blockedObject, blockedModel, blockedDiags := flattenCustomNotification(ctx, blockedCurrent, api.BlockedNotification)
	diags.Append(blockedDiags...)
	if diags.HasError() {
		return types.ObjectNull(deviceControlCustomNotificationsAttrTypes()), nil, diags
	}
	model.BlockedNotification = blockedObject
	model.blockedNotification = blockedModel

	var restrictedCurrent *deviceControlCustomNotification
	if current != nil {
		restrictedCurrent = current.restrictedNotification
	}
	restrictedObject, restrictedModel, restrictedDiags := flattenCustomNotification(ctx, restrictedCurrent, api.RestrictedNotification)
	diags.Append(restrictedDiags...)
	if diags.HasError() {
		return types.ObjectNull(deviceControlCustomNotificationsAttrTypes()), nil, diags
	}
	model.RestrictedNotification = restrictedObject
	model.restrictedNotification = restrictedModel

	if model.blockedNotification == nil && model.restrictedNotification == nil {
		return types.ObjectNull(deviceControlCustomNotificationsAttrTypes()), nil, diags
	}

	obj, objDiags := types.ObjectValueFrom(ctx, deviceControlCustomNotificationsAttrTypes(), model)
	diags.Append(objDiags...)
	if diags.HasError() {
		return types.ObjectNull(deviceControlCustomNotificationsAttrTypes()), nil, diags
	}

	return obj, &model, diags
}

func flattenCustomNotification(
	ctx context.Context,
	current *deviceControlCustomNotification,
	api *models.DeviceControlUSBCustomNotification,
) (types.Object, *deviceControlCustomNotification, diag.Diagnostics) {
	var diags diag.Diagnostics

	if api == nil {
		return types.ObjectNull(deviceControlCustomNotificationAttrTypes()), nil, diags
	}

	customNotification := deviceControlCustomNotification{
		UseCustom: types.BoolValue(false),
	}

	if api.UseCustom != nil {
		customNotification.UseCustom = types.BoolValue(*api.UseCustom)
	}

	if current != nil {
		customNotification.CustomMessage = utils.SetStringFromAPIIfNotEmpty(current.CustomMessage, pointerString(api.CustomMessage))
	} else {
		customNotification.CustomMessage = flex.StringPointerToFramework(api.CustomMessage)
	}

	customNotificationObject, objectDiags := types.ObjectValueFrom(
		ctx,
		deviceControlCustomNotificationAttrTypes(),
		customNotification,
	)
	diags.Append(objectDiags...)
	if diags.HasError() {
		return types.ObjectNull(deviceControlCustomNotificationAttrTypes()), nil, diags
	}

	return customNotificationObject, &customNotification, diags
}

func (m *deviceControlPolicyResourceModel) expandSettings(
	ctx context.Context,
	currentPolicy *models.DeviceControlPolicyV1,
) (*models.DeviceControlSettingsReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	existingByClassAndKey, existingIDs := buildExistingExceptionIndex(currentPolicy)
	usedIDs := map[string]struct{}{}

	apiClasses := make([]*models.DeviceControlUSBClassExceptionsReqV1, 0, len(m.settings.classes))

	for _, class := range m.settings.classes {
		classID := class.ID.ValueString()
		classAction := mapTerraformActionToAPI(class.Action.ValueString())

		apiClass := &models.DeviceControlUSBClassExceptionsReqV1{
			ID:         class.ID.ValueStringPointer(),
			Action:     &classAction,
			Exceptions: []*models.DeviceControlExceptionReqV1{},
		}

		for _, exception := range class.exceptions {
			apiException, exceptionDiags := expandDeviceControlException(exception)
			diags.Append(exceptionDiags...)
			if diags.HasError() {
				return nil, diags
			}

			exceptionID := ""
			if hasKnownNonEmptyString(exception.ID) {
				exceptionID = exception.ID.ValueString()
			} else {
				exceptionKey := exceptionIdentityKey(
					classID,
					exception.CombinedID.ValueString(),
					exception.VendorID.ValueString(),
					exception.VendorIDDecimal.ValueString(),
					exception.ProductID.ValueString(),
					exception.ProductIDDecimal.ValueString(),
					exception.SerialNumber.ValueString(),
				)

				if classExceptions, ok := existingByClassAndKey[classID]; ok {
					if candidateIDs, ok := classExceptions[exceptionKey]; ok {
						for _, candidateID := range candidateIDs {
							if _, alreadyUsed := usedIDs[candidateID]; alreadyUsed {
								continue
							}
							exceptionID = candidateID
							break
						}
					}
				}
			}

			if exceptionID != "" {
				apiException.ID = exceptionID
				usedIDs[exceptionID] = struct{}{}
			}

			apiClass.Exceptions = append(apiClass.Exceptions, apiException)
		}

		apiClasses = append(apiClasses, apiClass)
	}

	deleteExceptions := make([]string, 0, len(existingIDs))
	for exceptionID := range existingIDs {
		if _, keep := usedIDs[exceptionID]; keep {
			continue
		}
		deleteExceptions = append(deleteExceptions, exceptionID)
	}
	slices.Sort(deleteExceptions)

	enforcementMode := mapTerraformEnforcementModeToAPI(m.settings.EnforcementMode.ValueString())
	endUserNotification := m.settings.EndUserNotification.ValueString()

	settings := &models.DeviceControlSettingsReqV1{
		Classes:              apiClasses,
		DeleteExceptions:     deleteExceptions,
		EndUserNotification:  &endUserNotification,
		EnforcementMode:      &enforcementMode,
		EnhancedFileMetadata: m.settings.EnhancedFileMeta.ValueBool(),
	}

	settings.CustomNotifications = expandCustomNotifications(m.settings.customNotifications)

	return settings, diags
}

func expandDeviceControlException(model deviceControlExceptionModel) (*models.DeviceControlExceptionReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	apiException := &models.DeviceControlExceptionReqV1{
		Action:           mapTerraformActionToAPI(model.Action.ValueString()),
		CombinedID:       model.CombinedID.ValueString(),
		Description:      model.Description.ValueString(),
		ProductID:        model.ProductID.ValueString(),
		ProductIDDecimal: model.ProductIDDecimal.ValueString(),
		ProductName:      model.ProductName.ValueString(),
		SerialNumber:     model.SerialNumber.ValueString(),
		UseWildcard:      model.UseWildcard.ValueBool(),
		VendorID:         model.VendorID.ValueString(),
		VendorIDDecimal:  model.VendorIDDecimal.ValueString(),
		VendorName:       model.VendorName.ValueString(),
	}

	if hasKnownNonEmptyString(model.ExpirationTime) {
		expiration, err := time.Parse(time.RFC3339, model.ExpirationTime.ValueString())
		if err != nil {
			diags.AddError(
				"Invalid expiration_time",
				fmt.Sprintf("expiration_time %q must be in RFC3339 format", model.ExpirationTime.ValueString()),
			)
			return nil, diags
		}
		apiException.ExpirationTime = strfmt.DateTime(expiration)
	}

	return apiException, diags
}

func expandCustomNotifications(model *deviceControlCustomNotifications) *models.DeviceControlUSBCustomNotifications {
	if model == nil {
		return nil
	}

	customNotifications := &models.DeviceControlUSBCustomNotifications{}

	if model.blockedNotification != nil {
		customNotifications.BlockedNotification = expandCustomNotification(model.blockedNotification)
	}

	if model.restrictedNotification != nil {
		customNotifications.RestrictedNotification = expandCustomNotification(model.restrictedNotification)
	}

	if customNotifications.BlockedNotification == nil && customNotifications.RestrictedNotification == nil {
		return nil
	}

	return customNotifications
}

func expandCustomNotification(model *deviceControlCustomNotification) *models.DeviceControlUSBCustomNotification {
	if model == nil {
		return nil
	}

	customMessage := ""
	if hasKnownNonEmptyString(model.CustomMessage) {
		customMessage = model.CustomMessage.ValueString()
	}

	useCustom := model.UseCustom.ValueBool()
	return &models.DeviceControlUSBCustomNotification{
		UseCustom:     &useCustom,
		CustomMessage: &customMessage,
	}
}

func buildExistingExceptionIndex(
	policy *models.DeviceControlPolicyV1,
) (map[string]map[string][]string, map[string]struct{}) {
	byClassAndKey := map[string]map[string][]string{}
	allIDs := map[string]struct{}{}

	if policy == nil || policy.Settings == nil {
		return byClassAndKey, allIDs
	}

	for _, class := range policy.Settings.Classes {
		if class == nil || class.ID == nil {
			continue
		}
		classID := *class.ID

		if _, ok := byClassAndKey[classID]; !ok {
			byClassAndKey[classID] = map[string][]string{}
		}

		for _, exception := range class.Exceptions {
			if exception == nil || exception.ID == nil || *exception.ID == "" {
				continue
			}

			exceptionID := *exception.ID
			exceptionKey := exceptionIdentityKey(
				classID,
				exception.CombinedID,
				exception.VendorID,
				exception.VendorIDDecimal,
				exception.ProductID,
				exception.ProductIDDecimal,
				exception.SerialNumber,
			)

			byClassAndKey[classID][exceptionKey] = append(byClassAndKey[classID][exceptionKey], exceptionID)
			allIDs[exceptionID] = struct{}{}
		}
	}

	return byClassAndKey, allIDs
}

func exceptionIdentityKey(
	classID,
	combinedID,
	vendorID,
	vendorIDDecimal,
	productID,
	productIDDecimal,
	serialNumber string,
) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(classID)),
		strings.ToLower(strings.TrimSpace(combinedID)),
		strings.ToLower(strings.TrimSpace(vendorID)),
		strings.TrimSpace(vendorIDDecimal),
		strings.ToLower(strings.TrimSpace(productID)),
		strings.TrimSpace(productIDDecimal),
		strings.ToLower(strings.TrimSpace(serialNumber)),
	}, "|")
}

func mapAPIActionToTerraform(action string) string {
	switch action {
	case "FULL_BLOCK":
		return "BLOCK_ALL"
	case "READ_ONLY":
		return "BLOCK_WRITE_EXECUTE"
	default:
		return action
	}
}

func mapTerraformActionToAPI(action string) string {
	switch action {
	case "FULL_BLOCK":
		return "BLOCK_ALL"
	case "READ_ONLY":
		return "BLOCK_WRITE_EXECUTE"
	default:
		return action
	}
}

func mapEnforcementModeToTerraform(current types.String, apiEnforcementMode *string) string {
	if apiEnforcementMode == nil {
		if utils.IsKnown(current) {
			return current.ValueString()
		}
		return "MONITOR_ONLY"
	}

	if *apiEnforcementMode == "OFF" {
		if utils.IsKnown(current) {
			return current.ValueString()
		}
		return "MONITOR_ONLY"
	}

	return *apiEnforcementMode
}

func mapTerraformEnforcementModeToAPI(enforcementMode string) string {
	if enforcementMode == "OFF" {
		return "MONITOR_ONLY"
	}
	return enforcementMode
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func hasKnownNonEmptyString(value types.String) bool {
	return utils.IsKnown(value) && strings.TrimSpace(value.ValueString()) != ""
}

func (r *deviceControlPolicyResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *deviceControlPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_device_control_policy"
}

func (r *deviceControlPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Host Setup and Management",
			"Manages CrowdStrike Device Control policies that control USB device access on endpoints.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the device control policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the device control policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the device control policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the device control policy. One of: `Windows`, `Mac`, `Linux`. Changing this value requires replacing the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Mac", "Linux"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the policy is enabled.",
				Default:     booldefault.StaticBool(false),
			},
			"clone_id": schema.StringAttribute{
				Optional:    true,
				Description: "Policy ID to clone settings from at creation time. Changing this value requires replacing the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host group IDs to attach to the policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"settings": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Device control policy settings.",
				Attributes: map[string]schema.Attribute{
					"enforcement_mode": schema.StringAttribute{
						Required:    true,
						Description: "How the policy is enforced. One of: `MONITOR_ONLY`, `MONITOR_ENFORCE`.",
						Validators: []validator.String{
							stringvalidator.OneOf("MONITOR_ONLY", "MONITOR_ENFORCE"),
						},
					},
					"end_user_notification": schema.StringAttribute{
						Required:    true,
						Description: "Whether end users receive notifications. One of: `SILENT`, `NOTIFY_USER`.",
						Validators: []validator.String{
							stringvalidator.OneOf("SILENT", "NOTIFY_USER"),
						},
					},
					"enhanced_file_metadata": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Enable enhanced file metadata on the sensor.",
						Default:     booldefault.StaticBool(false),
					},
					"classes": schema.ListNestedAttribute{
						Required:    true,
						Description: "USB class policy configurations.",
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
						},
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"id": schema.StringAttribute{
									Required:    true,
									Description: "USB class ID. One of: `ANY`, `AUDIO_VIDEO`, `IMAGING`, `MASS_STORAGE`, `MOBILE`, `PRINTER`, `WIRELESS`.",
									Validators: []validator.String{
										stringvalidator.OneOf("ANY", "AUDIO_VIDEO", "IMAGING", "MASS_STORAGE", "MOBILE", "PRINTER", "WIRELESS"),
									},
								},
								"action": schema.StringAttribute{
									Required:    true,
									Description: "Action for this USB class. One of: `FULL_ACCESS`, `BLOCK_ALL`, `BLOCK_EXECUTE`, `BLOCK_WRITE_EXECUTE`.",
									Validators: []validator.String{
										stringvalidator.OneOf("FULL_ACCESS", "BLOCK_ALL", "BLOCK_EXECUTE", "BLOCK_WRITE_EXECUTE"),
									},
								},
								"exceptions": schema.ListNestedAttribute{
									Optional:    true,
									Description: "Exceptions to class actions.",
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"id": schema.StringAttribute{
												Computed:    true,
												Description: "API-generated identifier for the exception.",
											},
											"combined_id": schema.StringAttribute{
												Optional:    true,
												Description: "Combined identifier in the format `vendorID_productID_serialNumber`.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"vendor_id": schema.StringAttribute{
												Optional:    true,
												Description: "Hexadecimal vendor ID.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"vendor_id_decimal": schema.StringAttribute{
												Optional:    true,
												Description: "Decimal vendor ID.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"vendor_name": schema.StringAttribute{
												Optional:    true,
												Description: "Vendor name.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"product_id": schema.StringAttribute{
												Optional:    true,
												Description: "Hexadecimal product ID.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"product_id_decimal": schema.StringAttribute{
												Optional:    true,
												Description: "Decimal product ID.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"product_name": schema.StringAttribute{
												Optional:    true,
												Description: "Product name.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"serial_number": schema.StringAttribute{
												Optional:    true,
												Description: "USB serial number. Maximum length: 126.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
													stringvalidator.LengthAtMost(126),
												},
											},
											"description": schema.StringAttribute{
												Optional:    true,
												Description: "Exception description. Maximum length: 512.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
													stringvalidator.LengthAtMost(512),
												},
											},
											"action": schema.StringAttribute{
												Optional:    true,
												Description: "Exception-specific action override.",
												Validators: []validator.String{
													stringvalidator.OneOf("FULL_ACCESS", "BLOCK_ALL", "BLOCK_EXECUTE", "BLOCK_WRITE_EXECUTE"),
												},
											},
											"expiration_time": schema.StringAttribute{
												Optional:    true,
												Description: "Expiration timestamp in RFC3339 format.",
												Validators: []validator.String{
													fwvalidators.StringNotWhitespace(),
												},
											},
											"use_wildcard": schema.BoolAttribute{
												Optional:    true,
												Computed:    true,
												Description: "Enable wildcard matching for serial numbers.",
												Default:     booldefault.StaticBool(false),
											},
										},
									},
								},
							},
						},
					},
					"custom_notifications": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Custom end-user notifications.",
						Attributes: map[string]schema.Attribute{
							"blocked_notification": schema.SingleNestedAttribute{
								Optional:    true,
								Description: "Custom notification displayed when a USB device is blocked.",
								Attributes: map[string]schema.Attribute{
									"use_custom": schema.BoolAttribute{
										Required:    true,
										Description: "Whether to use a custom message.",
									},
									"custom_message": schema.StringAttribute{
										Optional:    true,
										Description: "Custom message text. Maximum length: 256.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
											stringvalidator.LengthAtMost(256),
										},
									},
								},
							},
							"restricted_notification": schema.SingleNestedAttribute{
								Optional:    true,
								Description: "Custom notification displayed when a USB device is restricted.",
								Attributes: map[string]schema.Attribute{
									"use_custom": schema.BoolAttribute{
										Required:    true,
										Description: "Whether to use a custom message.",
									},
									"custom_message": schema.StringAttribute{
										Optional:    true,
										Description: "Custom message text. Maximum length: 256.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
											stringvalidator.LengthAtMost(256),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *deviceControlPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Trace(ctx, "Starting device control policy create")

	var plan deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, settingsDiags := plan.expandSettings(ctx, nil)
	resp.Diagnostics.Append(settingsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := device_control_policies.CreateDeviceControlPoliciesParams{
		Context: ctx,
		Body: &models.DeviceControlCreatePoliciesV1{
			Resources: []*models.DeviceControlCreatePolicyReqV1{
				{
					Name:         plan.Name.ValueStringPointer(),
					Description:  plan.Description.ValueString(),
					PlatformName: plan.Platform.ValueStringPointer(),
					CloneID:      plan.CloneID.ValueString(),
					Settings:     settings,
				},
			},
		},
	}

	createResp, err := r.client.DeviceControlPolicies.CreateDeviceControlPolicies(&createRequest)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
		return
	}

	if createResp == nil || createResp.Payload == nil || len(createResp.Payload.Resources) == 0 || createResp.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, createResp.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	policyID := pointerString(createResp.Payload.Resources[0].ID)
	if policyID == "" {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	plan.ID = types.StringValue(policyID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		_, diag := r.setDeviceControlPolicyEnabled(ctx, policyID, "enable")
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	if len(plan.HostGroups.Elements()) > 0 {
		var groupsToAdd []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &groupsToAdd, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		_, diag := r.syncHostGroups(ctx, policyID, groupsToAdd, nil)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	policy, diags := r.getDeviceControlPolicy(ctx, policyID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *deviceControlPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting device control policy read")

	var state deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(state.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.getDeviceControlPolicy(ctx, state.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *deviceControlPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting device control policy update")

	var plan deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(state.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	currentPolicy, currentPolicyDiags := r.getDeviceControlPolicy(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(currentPolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, settingsDiags := plan.expandSettings(ctx, currentPolicy)
	resp.Diagnostics.Append(settingsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest := device_control_policies.UpdateDeviceControlPoliciesParams{
		Context: ctx,
		Body: &models.DeviceControlUpdatePoliciesReqV1{
			Resources: []*models.DeviceControlUpdatePolicyReqV1{
				{
					ID:          plan.ID.ValueStringPointer(),
					Name:        plan.Name.ValueString(),
					Description: plan.Description.ValueString(),
					Settings:    settings,
				},
			},
		},
	}

	updateResp, err := r.client.DeviceControlPolicies.UpdateDeviceControlPolicies(&updateRequest)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	if updateResp == nil || updateResp.Payload == nil || len(updateResp.Payload.Resources) == 0 || updateResp.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateResp.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		actionName := "disable"
		if plan.Enabled.ValueBool() {
			actionName = "enable"
		}

		_, diag := r.setDeviceControlPolicyEnabled(ctx, plan.ID.ValueString(), actionName)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	hostGroupsToAdd, hostGroupsToRemove, setDiags := utils.SetIDsToModify(ctx, plan.HostGroups, state.HostGroups)
	resp.Diagnostics.Append(setDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(hostGroupsToAdd) > 0 || len(hostGroupsToRemove) > 0 {
		_, diag := r.syncHostGroups(ctx, plan.ID.ValueString(), hostGroupsToAdd, hostGroupsToRemove)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	policy, diags := r.getDeviceControlPolicy(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *deviceControlPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Trace(ctx, "Starting device control policy delete")

	var state deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Enabled.ValueBool() {
		_, diag := r.setDeviceControlPolicyEnabled(ctx, state.ID.ValueString(), "disable")
		if diag != nil {
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diag)
			return
		}
	}

	_, err := r.client.DeviceControlPolicies.DeleteDeviceControlPolicies(
		&device_control_policies.DeleteDeviceControlPoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *deviceControlPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *deviceControlPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(config.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)

	for classIdx, class := range config.settings.classes {
		classPath := path.Root("settings").AtName("classes").AtListIndex(classIdx)
		classID := class.ID.ValueString()

		if hasKnownNonEmptyString(class.Action) && classID != "MASS_STORAGE" {
			actionValue := class.Action.ValueString()
			if actionValue == "BLOCK_EXECUTE" || actionValue == "BLOCK_WRITE_EXECUTE" {
				resp.Diagnostics.AddAttributeError(
					classPath.AtName("action"),
					"Invalid class action for USB class",
					fmt.Sprintf("action %q is only valid when class id is MASS_STORAGE", actionValue),
				)
			}
		}

		for exceptionIdx, exception := range class.exceptions {
			exceptionPath := classPath.AtName("exceptions").AtListIndex(exceptionIdx)

			hasCombinedID := hasKnownNonEmptyString(exception.CombinedID)
			hasVendor := hasKnownNonEmptyString(exception.VendorID) || hasKnownNonEmptyString(exception.VendorIDDecimal)
			hasProduct := hasKnownNonEmptyString(exception.ProductID) || hasKnownNonEmptyString(exception.ProductIDDecimal)

			if hasCombinedID && (hasVendor || hasProduct) {
				resp.Diagnostics.AddAttributeError(
					exceptionPath.AtName("combined_id"),
					"Invalid exception identifier combination",
					"combined_id cannot be used with vendor_id/vendor_id_decimal or product_id/product_id_decimal.",
				)
			}

			if hasKnownNonEmptyString(exception.Action) && classID != "MASS_STORAGE" {
				actionValue := exception.Action.ValueString()
				if actionValue == "BLOCK_EXECUTE" || actionValue == "BLOCK_WRITE_EXECUTE" {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("action"),
						"Invalid exception action for USB class",
						fmt.Sprintf("action %q is only valid when class id is MASS_STORAGE", actionValue),
					)
				}
			}

			if utils.IsKnown(exception.UseWildcard) && exception.UseWildcard.ValueBool() {
				if hasCombinedID {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("combined_id"),
						"Invalid wildcard configuration",
						"combined_id cannot be used when use_wildcard is true.",
					)
				}

				if !hasKnownNonEmptyString(exception.SerialNumber) {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("serial_number"),
						"Invalid wildcard configuration",
						"serial_number is required when use_wildcard is true.",
					)
				} else if strings.Contains(exception.SerialNumber.ValueString(), "**") {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("serial_number"),
						"Invalid wildcard configuration",
						"serial_number cannot contain double asterisks (**) when use_wildcard is true.",
					)
				}

				if !hasVendor || !hasProduct {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("use_wildcard"),
						"Invalid wildcard configuration",
						"use_wildcard requires both vendor and product identifiers (hex or decimal forms).",
					)
				}
			}

			if hasKnownNonEmptyString(exception.ExpirationTime) {
				expiration, err := time.Parse(time.RFC3339, exception.ExpirationTime.ValueString())
				if err != nil {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("expiration_time"),
						"Invalid expiration_time",
						"expiration_time must be a valid RFC3339 timestamp.",
					)
				} else if expiration.Before(time.Now().UTC()) {
					resp.Diagnostics.AddAttributeError(
						exceptionPath.AtName("expiration_time"),
						"Invalid expiration_time",
						"expiration_time must be in the future.",
					)
				}
			}
		}
	}

	if config.settings.customNotifications != nil {
		validateCustomNotificationConfig(
			path.Root("settings").AtName("custom_notifications").AtName("blocked_notification"),
			config.settings.customNotifications.blockedNotification,
			resp,
		)
		validateCustomNotificationConfig(
			path.Root("settings").AtName("custom_notifications").AtName("restricted_notification"),
			config.settings.customNotifications.restrictedNotification,
			resp,
		)
	}
}

func validateCustomNotificationConfig(
	notificationPath path.Path,
	notification *deviceControlCustomNotification,
	resp *resource.ValidateConfigResponse,
) {
	if notification == nil || !utils.IsKnown(notification.UseCustom) {
		return
	}

	if !notification.UseCustom.ValueBool() {
		return
	}

	if !hasKnownNonEmptyString(notification.CustomMessage) {
		resp.Diagnostics.AddAttributeError(
			notificationPath.AtName("custom_message"),
			"Missing custom_message",
			"custom_message must be set when use_custom is true.",
		)
	}
}

func (r *deviceControlPolicyResource) getDeviceControlPolicy(
	ctx context.Context,
	policyID string,
) (*models.DeviceControlPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.DeviceControlPolicies.GetDeviceControlPolicies(
		&device_control_policies.GetDeviceControlPoliciesParams{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *deviceControlPolicyResource) setDeviceControlPolicyEnabled(
	ctx context.Context,
	policyID string,
	actionName string,
) (*models.DeviceControlPolicyV1, diag.Diagnostic) {
	res, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
		&device_control_policies.PerformDeviceControlPoliciesActionParams{
			Context:    ctx,
			ActionName: actionName,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)
	if err != nil {
		return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
	}

	if res == nil || res.Payload == nil {
		return nil, tferrors.NewEmptyResponseError(tferrors.Update)
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		return nil, diag
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		return nil, nil
	}

	return res.Payload.Resources[0], nil
}

func (r *deviceControlPolicyResource) syncHostGroups(
	ctx context.Context,
	policyID string,
	groupsToAdd []string,
	groupsToRemove []string,
) (*models.DeviceControlPolicyV1, diag.Diagnostic) {
	var lastPolicy *models.DeviceControlPolicyV1

	performAction := func(actionName string, groups []string) diag.Diagnostic {
		name := "group_id"
		actionParameters := make([]*models.MsaspecActionParameter, 0, len(groups))

		for _, groupID := range groups {
			group := groupID
			actionParameters = append(actionParameters, &models.MsaspecActionParameter{
				Name:  &name,
				Value: &group,
			})
		}

		res, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
			&device_control_policies.PerformDeviceControlPoliciesActionParams{
				Context:    ctx,
				ActionName: actionName,
				Body: &models.MsaEntityActionRequestV2{
					Ids:              []string{policyID},
					ActionParameters: actionParameters,
				},
			},
		)
		if err != nil {
			return tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
		}

		if res == nil || res.Payload == nil {
			return tferrors.NewEmptyResponseError(tferrors.Update)
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
			return diag
		}

		if len(res.Payload.Resources) > 0 && res.Payload.Resources[0] != nil {
			lastPolicy = res.Payload.Resources[0]
		}

		return nil
	}

	if len(groupsToAdd) > 0 {
		if diag := performAction("add-host-group", groupsToAdd); diag != nil {
			return nil, diag
		}
	}

	if len(groupsToRemove) > 0 {
		if diag := performAction("remove-host-group", groupsToRemove); diag != nil {
			return nil, diag
		}
	}

	return lastPolicy, nil
}
