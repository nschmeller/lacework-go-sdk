//
// Author:: Salim Afiune Maya (<afiune@lacework.net>)
// Copyright:: Copyright 2020, Lacework Inc.
// License:: Apache License, Version 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package cmd

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/lacework/go-sdk/api"
	"github.com/lacework/go-sdk/internal/array"
)

var (
	// complianceGcpListCmd represents the list sub-command inside the gcp command
	complianceGcpListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List gcp projects and organizations",
		Long:    `List all GCP projects and organization IDs.`,
		RunE: func(_ *cobra.Command, args []string) error {
			cli.StartProgress("Fetching list of configured GCP projects...")
			response, err := cli.LwApi.Integrations.ListGcpCfg()
			cli.StopProgress()
			if err != nil {
				return errors.Wrap(err, "unable to list gcp projects/organizations")
			}

			return cliListGcpProjectsAndOrgs(&response)
		},
	}

	// complianceGcpListProjCmd represents the list-projects sub-command inside the gcp command
	complianceGcpListProjCmd = &cobra.Command{
		Use:     "list-projects <organization_id>",
		Aliases: []string{"list-proj"},
		Short:   "List projects from an organization",
		Long: `List all GCP projects from the provided organization ID.

Use the following command to list all GCP integrations in your account:

    lacework integrations list --type GCP_CFG

Then, select one GUID from an integration and visualize its details using the command:

    lacework integration show <int_guid>
`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var (
				orgID, _      = splitIDAndAlias(args[0])
				response, err = cli.LwApi.Compliance.ListGcpProjects(orgID)
			)
			if err != nil {
				return errors.Wrap(err, "unable to list gcp projects")
			}

			if len(response.Data) == 0 {
				return errors.New("no data found for the provided organization")
			}

			// ALLY-431 Workaround to split the Project ID and Project Alias
			// ultimately, we need to fix this in the API response
			cliCompGcpProjects := splitGcpProjectsApiResponse(response.Data[0])

			if cli.JSONOutput() {
				return cli.OutputJSON(cliCompGcpProjects)
			}

			rows := [][]string{}
			for _, project := range cliCompGcpProjects.Projects {
				rows = append(rows, []string{project.ID, project.Alias})
			}
			cli.OutputHuman(renderSimpleTable([]string{"Project ID", "Project Alias"}, rows))
			return nil
		},
	}

	// complianceGcpGetReportCmd represents the get-report sub-command inside the gcp command
	complianceGcpGetReportCmd = &cobra.Command{
		Use:     "get-report <organization_id> <project_id>",
		Aliases: []string{"get", "show"},
		PreRunE: func(_ *cobra.Command, args []string) error {
			if compCmdState.Csv {
				cli.EnableCSVOutput()
			}

			if len(args) > 2 {
				compCmdState.RecommendationID = args[2]
				if !validRecommendationID(compCmdState.RecommendationID) {
					return errors.Errorf("\n'%s' is not a valid recommendation id\n", compCmdState.RecommendationID)
				}
			}

			switch compCmdState.Type {
			case "CIS", "CIS12", "K8S", "HIPAA", "SOC", "PCI", "ISO_27001", "PCI_Rev2", "SOC_Rev2", "HIPAA_Rev2", "NIST_CSF",
				"NIST_800_53_REV4", "NIST_800_171_REV2":
				compCmdState.Type = fmt.Sprintf("GCP_%s", compCmdState.Type)
				return nil
			case "GCP_CIS", "GCP_CIS12", "GCP_K8S", "GCP_HIPAA", "GCP_SOC", "GCP_PCI", "GCP_ISO_27001", "GCP_PCI_Rev2", "GCP_SOC_Rev2",
				"GCP_HIPAA_Rev2", "GCP_GCP_NIST_CSF", "GCP_NIST_800_53_REV4", "GCP_NIST_800_171_REV2":
				return nil
			default:
				return errors.New("supported report types are: CIS, CIS12, K8S, HIPAA, SOC, ISO_27001, PCI, PCI_Rev2, SOC_Rev2, " +
					"HIPAA_Rev2, NIST_CSF, NIST_800_53_REV4 or NIST_800_171_REV2")
			}
		},
		Short: "Get the latest GCP compliance report",
		Long: `Get the latest compliance assessment report, these reports run on a regular schedule,
typically once a day. The available report formats are human-readable (default), json and pdf.

To list all GCP projects and organizations configured in your account:

    lacework compliance gcp list

To run an ad-hoc compliance assessment use the command:

    lacework compliance gcp run-assessment <project_id>

To show recommendation details and affected resources for a recommendation id:

    lacework compliance gcp get-report <organization_id> <project_id> [recommendation_id]
`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(_ *cobra.Command, args []string) error {
			var (
				// clean projectID and orgID if they were provided
				// with an Alias in between parentheses
				orgID, _     = splitIDAndAlias(args[0])
				projectID, _ = splitIDAndAlias(args[1])
				config       = api.ComplianceGcpReportConfig{
					OrganizationID: orgID,
					ProjectID:      projectID,
					Type:           compCmdState.Type,
				}
			)

			if compCmdState.Pdf {
				pdfName := fmt.Sprintf(
					"%s_Report_%s_%s_%s_%s.pdf",
					config.Type,
					config.OrganizationID,
					config.ProjectID,
					cli.Account, time.Now().Format("20060102150405"),
				)

				cli.StartProgress(" Downloading compliance report...")
				err := cli.LwApi.Compliance.DownloadGcpReportPDF(pdfName, config)
				cli.StopProgress()
				if err != nil {
					return errors.Wrap(err, "unable to get gcp pdf compliance report")
				}

				cli.OutputHuman("The GCP compliance report was downloaded at '%s'\n", pdfName)
				return nil
			}

			if compCmdState.Severity != "" {
				if !array.ContainsStr(api.ValidEventSeverities, compCmdState.Severity) {
					return errors.Errorf("the severity %s is not valid, use one of %s",
						compCmdState.Severity, strings.Join(api.ValidEventSeverities, ", "),
					)
				}
			}
			if compCmdState.Status != "" {
				if !array.ContainsStr(api.ValidComplianceStatus, compCmdState.Status) {
					return errors.Errorf("the status %s is not valid, use one of %s",
						compCmdState.Status, strings.Join(api.ValidComplianceStatus, ", "),
					)
				}
			}

			// diagonals are file separators and therefore we need to clean the organization
			// ID if it is "n/a" or we will create two directories "n/a/..."
			orgIDForCache := config.OrganizationID
			if config.OrganizationID == "n/a" {
				orgIDForCache = "not_applicable"
			}

			var (
				report   api.ComplianceGcpReport
				cacheKey = fmt.Sprintf("compliance/google/%s/%s/%s",
					orgIDForCache, config.ProjectID, config.Type)
			)
			expired := cli.ReadCachedAsset(cacheKey, &report)
			if expired {
				cli.StartProgress(" Getting compliance report...")
				response, err := cli.LwApi.Compliance.GetGcpReport(config)
				cli.StopProgress()
				if err != nil {
					return errors.Wrap(err, "unable to get gcp compliance report")
				}

				if len(response.Data) == 0 {
					return errors.New("no data found in the report")
				}

				report = response.Data[0]

				cli.WriteAssetToCache(cacheKey, time.Now().Add(time.Minute*30), report)
			}

			filteredOutput := ""

			if complianceFiltersEnabled() {
				report.Recommendations, filteredOutput = filterRecommendations(report.Recommendations)
			}

			if cli.JSONOutput() && compCmdState.RecommendationID == "" {
				return cli.OutputJSON(report)
			}

			if cli.CSVOutput() {
				recommendations := complianceCSVReportRecommendationsTable(
					&complianceCSVReportDetails{
						TenantName:      report.OrganizationName,
						TenantID:        report.OrganizationID,
						AccountName:     report.ProjectName,
						AccountID:       report.ProjectID,
						ReportType:      report.ReportType,
						ReportTime:      report.ReportTime,
						Recommendations: report.Recommendations,
					},
				)

				return cli.OutputCSV(
					[]string{"Report_Type", "Report_Time", "Organization",
						"Project", "Section", "ID", "Recommendation", "Status",
						"Severity", "Resource", "Region", "Reason"},
					recommendations,
				)
			}

			// If RecommendationID is provided, output resources matching that id
			if compCmdState.RecommendationID != "" {
				return outputResourcesByRecommendationID(report)
			}

			recommendations := complianceReportRecommendationsTable(report.Recommendations)
			cli.OutputHuman("\n")
			cli.OutputHuman(
				buildComplianceReportTable(
					complianceGcpReportDetailsTable(&report),
					complianceReportSummaryTable(report.Summary),
					recommendations,
					filteredOutput,
				),
			)
			return nil
		},
	}

	// complianceGcpRunAssessmentCmd represents the run-assessment sub-command inside the gcp command
	complianceGcpRunAssessmentCmd = &cobra.Command{
		Use:     "run-assessment <org_or_project_id>",
		Aliases: []string{"run"},
		Short:   "Run a new GCP compliance assessment",
		Long: `Run a compliance assessment for the provided GCP organization or project.

To list all GCP projects and organizations configured in your account:

    lacework compliance gcp list`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			response, err := cli.LwApi.Compliance.RunGcpReport(args[0])
			if err != nil {
				return errors.Wrap(err, "unable to run gcp compliance assessment")
			}

			if cli.JSONOutput() {
				return cli.OutputJSON(response)
			}

			cli.OutputHuman("A new GCP compliance assessment has been initiated.\n")
			cli.OutputHuman("\n")
			cli.OutputHuman(
				renderSimpleTable(
					[]string{"INTEGRATION GUID", "ORG/PROJECT ID"},
					[][]string{[]string{response.IntgGuid, args[0]}},
				),
			)
			return nil
		},
	}
	// complianceGcpDisableReportCmd represents the disable-report sub-command inside the aws command
	// experimental feature
	complianceGcpDisableReportCmd = &cobra.Command{
		Use:     "disable-report <report_type>",
		Hidden:  true,
		Aliases: []string{"disable"},
		Short:   "Disable all recommendations for a given report type",
		Long: `Disable all recommendations for a given report type.
Supported report types are: CIS_1_0, CIS_1_2

To show the current status of recommendations in a report run:
	lacework compliance gcp status CIS_1_2

To disable all recommendations for CIS_1_2 report run:
	lacework compliance gcp disable CIS_1_2
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "CIS", "CIS_1_0", "GCP_CIS":
				args[0] = "CIS_1_0"
				return nil
			case "CIS_1_2", "GCP_CIS12":
				args[0] = "CIS_1_2"
				return nil
			default:
				return errors.New("supported report types are: CIS_1_0, CIS_1_2")
			}
		},
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			// prompt for changes
			proceed, err := complianceGcpDisableReportDisplayChanges(args[0])
			if err != nil {
				return errors.Wrap(err, "unable to confirm disable")
			}
			if !proceed {
				return nil
			}

			schema, err := fetchCachedGcpComplianceReportSchema(args[0])
			if err != nil {
				return errors.Wrap(err, "unable to fetch gcp compliance report schema")
			}

			// set state of all recommendations in this report to disabled
			patchReq := api.NewRecommendationV1State(schema, false)
			cli.StartProgress("disabling recommendations...")
			response, err := cli.LwApi.Recommendations.Gcp.Patch(patchReq)
			cli.StopProgress()
			if err != nil {
				return errors.Wrap(err, "unable to patch gcp recommendations")
			}

			var cacheKey = fmt.Sprintf("compliance/gcp/schema/%s", args[0])
			cli.WriteAssetToCache(cacheKey, time.Now().Add(time.Minute*30), response.RecommendationList())
			cli.OutputHuman("All recommendations for report %s have been disabled\n", args[0])
			return nil
		},
	}

	// complianceGcpEnableReportCmd represents the enable-report sub-command inside the aws command
	// experimental feature
	complianceGcpEnableReportCmd = &cobra.Command{
		Use:     "enable-report <report_type>",
		Hidden:  true,
		Aliases: []string{"enable"},
		Short:   "Enable all recommendations for a given report type",
		Long: `Enable all recommendations for a given report type.
Supported report types are: CIS_1_0, CIS_1_2

To show the current status of recommendations in a report run:
	lacework compliance gcp status CIS_1_2

To enable all recommendations for CIS_1_2 report run:
	lacework compliance gcp enable CIS_1_2
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "CIS", "CIS_1_0", "GCP_CIS":
				args[0] = "CIS_1_0"
				return nil
			case "CIS_1_2", "GCP_CIS12":
				args[0] = "CIS_1_2"
				return nil
			default:
				return errors.New("supported report types are: CIS_1_0, CIS_1_2")
			}
		},
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {

			schema, err := fetchCachedGcpComplianceReportSchema(args[0])
			if err != nil {
				return errors.Wrap(err, "unable to fetch gcp compliance report schema")
			}

			// set state of all recommendations in this report to enabled
			patchReq := api.NewRecommendationV1State(schema, true)
			cli.StartProgress("enabling recommendations...")
			response, err := cli.LwApi.Recommendations.Gcp.Patch(patchReq)
			cli.StopProgress()
			if err != nil {
				return errors.Wrap(err, "unable to patch gcp recommendations")
			}

			var cacheKey = fmt.Sprintf("compliance/gcp/schema/%s", args[0])
			cli.WriteAssetToCache(cacheKey, time.Now().Add(time.Minute*30), response.RecommendationList())
			cli.OutputHuman("All recommendations for report %s have been enabled\n", args[0])
			return nil
		},
	}

	// complianceGcpReportStatusCmd represents the report-status sub-command inside the aws command
	// experimental feature
	complianceGcpReportStatusCmd = &cobra.Command{
		Use:     "report-status <report_type>",
		Hidden:  true,
		Aliases: []string{"status"},
		Short:   "Show the status of recommendations for a given report type",
		Long: `Show the status of recommendations for a given report type.
Supported report types are: CIS_1_0, CIS_1_2

To show the current status of recommendations in a report run:
	lacework compliance gcp status CIS_1_2

The output from status with the --json flag can be used in the body of PATCH api/v1/external/recommendations/gcp
	lacework compliance gcp status CIS_1_2 --json
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "CIS", "CIS_1_0", "GCP_CIS":
				args[0] = "CIS_1_0"
				return nil
			case "CIS_1_2", "GCP_CIS12":
				args[0] = "CIS_1_2"
				return nil
			default:
				return errors.New("supported report types are: CIS_1_0, CIS_1_2")
			}
		},
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var rows [][]string
			report, err := fetchCachedGcpComplianceReportSchema(args[0])
			if err != nil {
				return errors.Wrap(err, "unable to fetch gcp compliance report schema")
			}

			if cli.JSONOutput() {
				return cli.OutputJSON(api.NewRecommendationV1(report))
			}

			for _, r := range report {
				rows = append(rows, []string{r.ID, strconv.FormatBool(r.State)})
			}

			cli.OutputHuman(renderOneLineCustomTable(args[0],
				renderCustomTable([]string{}, rows,
					tableFunc(func(t *tablewriter.Table) {
						t.SetBorder(false)
						t.SetColumnSeparator(" ")
						t.SetAutoWrapText(false)
						t.SetAlignment(tablewriter.ALIGN_LEFT)
					}),
				),
				tableFunc(func(t *tablewriter.Table) {
					t.SetBorder(false)
					t.SetAutoWrapText(false)
				}),
			))
			return nil
		},
	}
)

func init() {
	// add sub-commands to the gcp command
	complianceGcpCmd.AddCommand(complianceGcpListCmd)
	complianceGcpCmd.AddCommand(complianceGcpListProjCmd)
	complianceGcpCmd.AddCommand(complianceGcpRunAssessmentCmd)
	complianceGcpCmd.AddCommand(complianceGcpGetReportCmd)

	// Experimental Commands
	complianceGcpCmd.AddCommand(complianceGcpReportStatusCmd)
	complianceGcpCmd.AddCommand(complianceGcpDisableReportCmd)
	complianceGcpCmd.AddCommand(complianceGcpEnableReportCmd)

	complianceGcpGetReportCmd.Flags().BoolVar(&compCmdState.Details, "details", false,
		"increase details about the compliance report",
	)
	complianceGcpGetReportCmd.Flags().BoolVar(&compCmdState.Pdf, "pdf", false,
		"download report in PDF format",
	)

	// Output the report in CSV format
	complianceGcpGetReportCmd.Flags().BoolVar(&compCmdState.Csv, "csv", false,
		"output report in CSV format",
	)

	// GCP report types: GCP_CIS, GCP_CIS12, GCP_K8S, GCP_HIPAA, GCP_SOC, or GCP_PCI.
	complianceGcpGetReportCmd.Flags().StringVar(&compCmdState.Type, "type", "CIS",
		"report type to display, supported types: CIS, CIS12, K8S, HIPAA, SOC, or PCI",
	)

	complianceGcpGetReportCmd.Flags().StringSliceVar(&compCmdState.Category, "category", []string{},
		"filter report details by category (storage, networking, identity-and-access-management, ...)",
	)

	complianceGcpGetReportCmd.Flags().StringSliceVar(&compCmdState.Service, "service", []string{},
		"filter report details by service (gcp:storage:bucket, gcp:kms:cryptoKey, gcp:project, ...)",
	)

	complianceGcpGetReportCmd.Flags().StringVar(&compCmdState.Severity, "severity", "",
		fmt.Sprintf("filter report details by severity threshold (%s)",
			strings.Join(api.ValidEventSeverities, ", ")),
	)

	complianceGcpGetReportCmd.Flags().StringVar(&compCmdState.Status, "status", "",
		fmt.Sprintf("filter report details by status (%s)",
			strings.Join(api.ValidComplianceStatus, ", ")),
	)
}

// Simple helper to prompt for approval after disable request
func complianceGcpDisableReportCmdPrompt(arg string) (int, error) {
	var message string

	switch arg {
	case "CIS", "CIS_1_0", "GCP_CIS":
		message = `WARNING! Disabling all recommendations for CIS_1_0 will disable the following reports and its corresponding compliance alerts:
  GCP CIS Benchmark
  PCI Benchmark
  SOC 2 Report

  Would you like to proceed?
  `
	case "CIS_1_2", "GCP_CIS12":
		message = `WARNING! Disabling all recommendations for CIS_1_2 will disable the following reports and its corresponding compliance alerts:
  GCP CIS Benchmark 1.2
  HIPAA Report Rev2
  PCI Benchmark Rev2
  SOC 2 Report Rev2
  ISO27001 Report
  NIST 800-171 rev2 Report
  NIST 800-53 rev4 Report
  NIST CSF rev2 Report

  Would you like to proceed?
  `
	}

	options := []string{
		"Proceed with disable",
		"Quit",
	}

	var answer int
	err := SurveyQuestionInteractiveOnly(SurveyQuestionWithValidationArgs{
		Prompt: &survey.Select{
			Message: message,
			Options: options,
		},
		Response: &answer,
	})

	return answer, err
}

func complianceGcpDisableReportDisplayChanges(arg string) (bool, error) {
	answer, err := complianceGcpDisableReportCmdPrompt(arg)
	if err != nil {
		return false, err
	}
	return answer == 0, nil
}

func complianceGcpReportDetailsTable(report *api.ComplianceGcpReport) [][]string {
	return [][]string{
		[]string{"Report Type", report.ReportType},
		[]string{"Report Title", report.ReportTitle},
		[]string{"Organization ID", report.OrganizationID},
		[]string{"Organization Name", report.OrganizationName},
		[]string{"Project ID", report.ProjectID},
		[]string{"Project Name", report.ProjectName},
		[]string{"Report Time", report.ReportTime.UTC().Format(time.RFC3339)},
	}
}

// ALLY-431 Workaround to split the Project ID and Project Alias
// ultimately, we need to fix this in the API response
func splitGcpProjectsApiResponse(gcpInfo api.CompGcpProjects) cliComplianceGcpInfo {
	var (
		orgID, orgAlias = splitIDAndAlias(gcpInfo.Organization)
		cliGcpInfo      = cliComplianceGcpInfo{
			Organization: cliComplianceIDAlias{orgID, orgAlias},
			Projects:     make([]cliComplianceIDAlias, 0),
		}
	)

	for _, project := range gcpInfo.Projects {
		id, alias := splitIDAndAlias(project)
		cliGcpInfo.Projects = append(cliGcpInfo.Projects, cliComplianceIDAlias{id, alias})
	}

	return cliGcpInfo
}

// @afiune we use named return in this function to be explicit about what is it
// that the function is returning, id and alias respectively
func splitIDAndAlias(text string) (id string, alias string) {
	// Getting alias from text
	aliasRegex := regexp.MustCompile(`\((.*?)\)`)
	aliasBytes := aliasRegex.Find([]byte(text))
	if len(aliasBytes) == 0 {
		// if we couldn't get the alias from the provided text
		// it means that the entire text is the id
		id = text
		return
	}
	alias = string(aliasBytes)
	alias = strings.Trim(alias, "(")
	alias = strings.Trim(alias, ")")

	// Getting id from text
	idRegex := regexp.MustCompile(`^(.*?)\(`)
	idBytes := idRegex.Find([]byte(text))
	id = string(idBytes)
	id = strings.Trim(id, "(")
	id = strings.TrimSpace(id)

	cli.Log.Infow("splitted", "text", text, "id", id, "alias", alias)
	return
}

func getGcpAccounts(orgID, status string) []gcpProject {
	var accounts []gcpProject

	cli.StartProgress(fmt.Sprintf("Fetching compliance information about %s organization...", orgID))
	projectsResponse, err := cli.LwApi.Compliance.ListGcpProjects(orgID)
	cli.StopProgress()
	if err != nil {
		cli.Log.Warnw("unable to list gcp projects", "org_id", orgID, "error", err.Error())
		return accounts
	}
	for _, projects := range projectsResponse.Data {
		for _, project := range projects.Projects {
			projectID, _ := splitIDAndAlias(project)
			accounts = append(accounts, gcpProject{
				OrganizationID: orgID,
				ProjectID:      projectID,
				Status:         status,
			})
		}
	}
	return accounts
}

type cliComplianceGcpInfo struct {
	Organization cliComplianceIDAlias   `json:"organization"`
	Projects     []cliComplianceIDAlias `json:"projects"`
}

type cliComplianceIDAlias struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
}

type gcpProject struct {
	ProjectID      string `json:"project_id"`
	OrganizationID string `json:"organization_id"`
	Status         string `json:"status"`
}

func extractGcpProjects(response *api.GcpIntegrationsResponse) []gcpProject {
	var gcpAccounts []gcpProject

	for _, gcp := range response.Data {
		// if organization account, fetch the project ids
		if gcp.Data.IDType == "ORGANIZATION" {
			gcpAccounts = append(gcpAccounts, getGcpAccounts(gcp.Data.ID, gcp.Status())...)
		} else if containsDuplicateProjectID(gcpAccounts, gcp.Data.ID) {
			cli.Log.Warnw("duplicate gcp project", "integration_guid", gcp.IntgGuid, "project", gcp.Data.ID)
			continue
		} else {
			gcpIntegration := gcpProject{
				OrganizationID: "n/a",
				ProjectID:      gcp.Data.ID,
				Status:         gcp.Status(),
			}
			gcpAccounts = append(gcpAccounts, gcpIntegration)
		}
	}

	sort.Slice(gcpAccounts, func(i, j int) bool {
		switch strings.Compare(gcpAccounts[i].OrganizationID, gcpAccounts[j].OrganizationID) {
		case -1:
			return true
		case 1:
			return false
		}
		return gcpAccounts[i].ProjectID < gcpAccounts[j].ProjectID
	})

	return gcpAccounts
}

func containsDuplicateProjectID(gcpAccounts []gcpProject, projectID string) bool {
	for _, value := range gcpAccounts {
		if projectID == value.ProjectID {
			return true
		}
	}
	return false
}

func cliListGcpProjectsAndOrgs(response *api.GcpIntegrationsResponse) error {
	jsonOut := struct {
		Projects []gcpProject `json:"gcp_projects"`
	}{Projects: make([]gcpProject, 0)}

	if response == nil || len(response.Data) == 0 {
		if cli.JSONOutput() {
			return cli.OutputJSON(jsonOut)
		}

		msg := `There are no GCP integrations configured in your account.

Get started by integrating your GCP to analyze configuration compliance using the command:

    lacework integration create

If you prefer to configure the integration via the WebUI, log in to your account at:

    https://%s.lacework.net

Then navigate to Settings > Integrations > Cloud Accounts.
`
		cli.OutputHuman(fmt.Sprintf(msg, cli.Account))
		return nil
	}

	if cli.JSONOutput() {
		jsonOut.Projects = extractGcpProjects(response)
		return cli.OutputJSON(jsonOut)
	}

	rows := [][]string{}
	for _, gcp := range extractGcpProjects(response) {
		rows = append(rows, []string{gcp.OrganizationID, gcp.ProjectID, gcp.Status})
	}

	cli.OutputHuman(renderSimpleTable([]string{"Organization ID", "Project ID", "Status"}, rows))
	return nil
}

func fetchCachedGcpComplianceReportSchema(reportType string) (response []api.RecommendationV1, err error) {
	var cacheKey = fmt.Sprintf("compliance/gcp/schema/%s", reportType)

	expired := cli.ReadCachedAsset(cacheKey, &response)
	if expired {
		cli.StartProgress("Fetching compliance report schema...")
		response, err = cli.LwApi.Recommendations.Gcp.GetReport(reportType)
		cli.StopProgress()
		if err != nil {
			return nil, errors.Wrap(err, "unable to get GCP compliance report schema")
		}

		if len(response) == 0 {
			return nil, errors.New("no data found in the report")
		}

		cli.WriteAssetToCache(cacheKey, time.Now().Add(time.Minute*30), response)
	}
	return
}
