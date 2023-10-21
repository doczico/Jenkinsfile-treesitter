function prefixGroovyRules(rules) {
  const prefixed = {};
  for (const rule in rules) {
    prefixed['groovy_' + rule] = rules[rule];
  }
  return prefixed;
}
const groovyGrammar = require('tree-sitter-groovy');
const prefixedGroovyRules = prefixGroovyRules(groovyGrammar.rules);

module.exports = grammar({
  name: 'Jenkinsfile',
  extras: ($) => [$.line_comment, $.block_comment, /\s/],
  // Include the groovy grammar
  externals: $ => [
     $._groovy_command,
     $._groovy_block
   ],

  rules: {
    // Entry point
    source_file: $ => repeat(choice(
    $.pipeline_block,
    $.script_block,
    )),
    prefixedGroovyRules, 
    script_block: $ => seq(
      'script',
      '{',
      $.groovy_code,
      '}'
    ),
    pipeline_block: $ => seq(
      'pipeline',
      '{',
      repeat(choice(
        $.agent_section,
        $.stages_section,
        $.post_section,
        $.environment_section,
        $.options_section,
        $.parameters_section,
        $.triggers_section,
        $.tools_section,
        $.libraries_section
      )),
      '}'
    ),

    agent_section: $ => seq(
      'agent',
      '{',
      // ... further details about the agent can be added here
      '}'
    ),

    stages_section: $ => seq(
      'stages',
      '{',
      repeat($.stage_block),
      '}'
    ),

    stage_block: $ => seq(
      'stage',
      '(',
      // This captures the name of the stage, e.g., 'Build'
      $.string,
      ')',
      '{',
      repeat(choice(
        $.steps_block,
        $.post_section,
        $.when_section
        // ... other stage-specific sections
      )),
      '}'
    ),

    steps_block: $ => seq(
      'steps',
      '{',
      repeat($._step_expression),
      '}'
    ),

    _step_expression: $ => choice(
      $.jenkinsfile_built_in_variable,
      $.jenkinsfile_option,
      $.jenkinsfile_core_step,
      $.jenkinsfile_pipeline_step,
      $.jenkinsfile_docker_config
    ),

    jenkinsfile_built_in_variable: $ => token('currentBuild'),
    // ... (rest of the grammar remains the same)


    jenkinsfile_section: $ => token(choice(
      'pipeline', 'agent', 'stages', 'steps', 'post'
    )),

    jenkinsfile_directive: $ => token(choice(
      'environment', 'options', 'parameters', 'triggers', 'stage', 'tools', 'input', 'when', 'libraries'
    )),

    jenkinsfile_option: $ => seq(
      token(choice(
        'buildDiscarder', 'disableConcurrentBuilds', 'overrideIndexTriggers', 'skipDefaultCheckout',
        'skipStagesAfterUnstable', 'checkoutToSubdirectory', 'timeout', 'retry', 'timestamps',
        'disableResume', 'newContainerPerStage', 'preserveStashes', 'quietPeriod', 'parallelsAlwaysFailFast'
      )),
      optional($.jenkinsfile_option_params)
    ),

    jenkinsfile_option_params: $ => seq(
      '(',
      // This can be expanded to capture specific parameters or general Groovy expressions.
      repeat($._expression),
      ')'
    ),

    jenkinsfile_core_step: $ => token(choice(
      'checkout', 'docker', 'dockerfile', 'node', 'scm', 'sh', 'stage', 'parallel', 'steps', 'step', 'tool',
      'always', 'changed', 'failure', 'success', 'unstable', 'aborted', 'unsuccessful', 'regression', 'fixed', 'cleanup'
    )),

    jenkinsfile_pipeline_step: $ => token(choice(
      'Applitools', 'ArtifactoryGradleBuild', 'Consul', 'MavenDescriptorStep', 'OneSky', 'VersionNumber',
      'ViolationsToBitbucketServer', 'ViolationsToGitHub', 'ViolationsToGitLab', '_OcAction', '_OcContextInit',
      '_OcWatch', 'acceptGitLabMR', 'acsDeploy', 'activateDTConfiguration', 'addBadge', 'addErrorBadge',
      'addGitLabMRComment', 'addInfoBadge', 'addInteractivePromotion', 'addShortText', 'addWarningBadge',
      'allure', 'anchore', 'androidApkMove', 'androidApkUpload', 'androidLint', 'ansiColor', 'ansiblePlaybook',
      'ansibleTower', 'ansibleVault', 'appMonBuildEnvironment', 'appMonPublishTestResults', 'appMonRegisterTestRun',
      'applatix', 'approveReceivedEvent', 'approveRequestedEvent', 'aqua', 'archive', 'archiveArtifacts',
      'arestocats', 'artifactResolver', 'artifactoryDistributeBuild', 'artifactoryDownload', 'artifactoryMavenBuild',
      'artifactoryPromoteBuild', 'artifactoryUpload', 'awaitDeployment', 'awaitDeploymentCompletion',
      'awsCodeBuild', 'awsIdentity', 'azureCLI', 'azureDownload', 'azureFunctionAppPublish', 'azureUpload',
      'azureVMSSUpdate', 'azureVMSSUpdateInstances', 'azureWebAppPublish', 'backlogPullRequest', 'bat',
      'bearychatSend', 'benchmark', 'bitbucketStatusNotify', 'blazeMeterTest', 'build', 'buildBamboo', 'buildImage',
      'bzt', 'cache', 'catchError', 'cbt', 'cbtScreenshotsTest', 'cbtSeleniumTest', 'cfInvalidate', 'cfnCreateChangeSet',
      'cfnDelete', 'cfnDeleteStackSet', 'cfnDescribe', 'cfnExecuteChangeSet', 'cfnExports', 'cfnUpdate',
      'cfnUpdateStackSet', 'cfnValidate', 'changeAsmVer', 'checkstyle', 'chefSinatraStep', 'cifsPublisher',
      'cleanWs', 'cleanup', 'cloudshareDockerMachine', 'cm', 'cmake', 'cmakeBuild', 'cobertura', 'codefreshLaunch',
      'codefreshRun', 'codescene', 'codesonar', 'collectEnv', 'conanAddRemote', 'conanAddUser', 'configFileProvider',
      'container', 'containerLog', 'contrastAgent', 'contrastVerification', 'copy', 'copyArtifacts', 'coverityResults',
      'cpack', 'createDeploymentEvent', 'createEnvironment', 'createEvent', 'createMemoryDump', 'createSummary',
      'createThreadDump', 'crxBuild', 'crxDeploy', 'crxDownload', 'crxReplicate', 'crxValidate', 'ctest', 'ctmInitiatePipeline',
      'ctmPostPiData', 'ctmSetPiData', 'cucumber', 'cucumberSlackSend', 'currentNamespace', 'debianPbuilder',
      'deleteDir', 'dependencyCheckAnalyzer', 'dependencyCheckPublisher', 'dependencyCheckUpdateOnly',
      'dependencyTrackPublisher', 'deployAPI', 'deployArtifacts', 'deployLambda', 'dingding', 'dir', 'disk',
      'dockerFingerprintFrom', 'dockerFingerprintRun', 'dockerNode', 'dockerPullStep', 'dockerPushStep',
      'dockerPushWithProxyStep', 'doktor', 'downloadProgetPackage', 'downstreamPublisher', 'dropbox',
      'dry', 'ec2', 'ec2ShareAmi', 'echo', 'ecrLogin', 'emailext', 'emailextrecipients', 'envVarsForTool', 'error',
      'evaluateGate', 'eventSourceLambda', 'executeCerberusCampaign', 'exportPackages', 'exportProjects',
      'exws', 'exwsAllocate', 'figlet', 'fileExists', 'fileOperations', 'findFiles', 'findbugs', 'fingerprint',
      'flywayrunner', 'ftp', 'ftpPublisher', 'gatlingArchive', 'getArtifactoryServer', 'getContext', 'getLastChangesPublisher',
      'git', 'gitbisect', 'githubNotify', 'gitlabBuilds', 'gitlabCommitStatus', 'googleCloudBuild', 'googleStorageDownload',
      'googleStorageUpload', 'gprbuild', 'greet', 'hipchatSend', 'http', 'httpRequest', 'hub_detect', 'hub_scan',
      'hub_scan_failure', 'hubotApprove', 'hubotSend', 'importPackages', 'importProjects', 'inNamespace',
      'inSession', 'initConanClient', 'input', 'invokeLambda', 'isUnix', 'ispwOperation', 'ispwRegisterWebhook',
      'ispwWaitForWebhook', 'jacoco', 'jdbc', 'jiraAddComment', 'jiraAddWatcher', 'jiraAssignIssue', 'jiraAssignableUserSearch',
      'jiraComment', 'jiraDeleteAttachment', 'jiraDeleteIssueLink', 'jiraDeleteIssueRemoteLink', 'jiraDeleteIssueRemoteLinks',
      'jiraDownloadAttachment', 'jiraEditComment', 'jiraEditComponent', 'jiraEditIssue', 'jiraEditVersion',
      'jiraGetAttachmentInfo', 'jiraGetComment', 'jiraGetComments', 'jiraGetComponent', 'jiraGetComponentIssueCount',
      'jiraGetFields', 'jiraGetIssue', 'jiraGetIssueLink', 'jiraGetIssueLinkTypes', 'jiraGetIssueRemoteLink',
      'jiraGetIssueRemoteLinks', 'jiraGetIssueTransitions', 'jiraGetIssueWatches', 'jiraGetProject',
      'jiraGetProjectComponents', 'jiraGetProjectStatuses', 'jiraGetProjectVersions', 'jiraGetProjects',
      'jiraGetVersion', 'jiraIssueSelector', 'jiraJqlSearch', 'jiraLinkIssues', 'jiraNewComponent', 'jiraNewIssue',
      'jiraNewIssueRemoteLink', 'jiraNewIssues', 'jiraNewVersion', 'jiraNotifyIssue', 'jiraSearch', 'jiraTransitionIssue',
      'jiraUploadAttachment', 'jiraUserSearch', 'jmhReport', 'jobDsl', 'junit', 'klocworkBuildSpecGeneration',
      'klocworkIncremental', 'klocworkIntegrationStep1', 'klocworkIntegrationStep2', 'klocworkIssueSync',
      'klocworkQualityGateway', 'klocworkWrapper', 'kubernetesApply', 'kubernetesDeploy', 'lastChanges',
      'library', 'libraryResource', 'liquibaseDbDoc', 'liquibaseRollback', 'liquibaseUpdate', 'listAWSAccounts',
      'livingDocs', 'loadRunnerTest', 'lock', 'logstashSend', 'mail', 'marathon', 'mattermostSend', 'memoryMap',
      'milestone', 'mockLoad', 'newArtifactoryServer', 'newBuildInfo', 'newGradleBuild', 'newMavenBuild',
      'nexusArtifactUploader', 'nexusPolicyEvaluation', 'nexusPublisher', 'node', 'nodejs', 'nodesByLabel',
      'notifyBitbucket', 'notifyDeploymon', 'notifyOTC', 'nunit', 'nvm', 'octoPerfTest', 'office365ConnectorSend',
      'openTasks', 'openshiftBuild', 'openshiftCreateResource', 'openshiftDeleteResourceByJsonYaml',
      'openshiftDeleteResourceByKey', 'openshiftDeleteResourceByLabels', 'openshiftDeploy', 'openshiftExec',
      'openshiftImageStream', 'openshiftScale', 'openshiftTag', 'openshiftVerifyBuild', 'openshiftVerifyDeployment',
      'openshiftVerifyService', 'openstackMachine', 'osfBuilderSuiteForSFCCDeploy', 'p4', 'p4approve',
      'p4publish', 'p4sync', 'p4tag', 'p4unshelve', 'pagerduty', 'parasoftFindings', 'pcBuild', 'pdrone', 'perfReport',
      'perfSigReports', 'perfpublisher', 'plot', 'pmd', 'podTemplate', 'powershell', 'pragprog', 'pretestedIntegrationPublisher',
      'properties', 'protecodesc', 'publishATX', 'publishBrakeman', 'publishBuildInfo', 'publishBuildRecord',
      'publishConfluence', 'publishDeployRecord', 'publishETLogs', 'publishEventQ', 'publishGenerators',
      'publishHTML', 'publishLambda', 'publishLastChanges', 'publishSQResults', 'publishStoplight', 'publishTMS',
      'publishTRF', 'publishTestResult', 'publishTraceAnalysis', 'publishUNIT', 'publishValgrind', 'pullPerfSigReports',
      'puppetCode', 'puppetHiera', 'puppetJob', 'puppetQuery', 'pushImage', 'pushToCloudFoundry', 'pwd', 'pybat',
      'pysh', 'qc', 'queryModuleBuildRequest', 'questavrm', 'r', 'radargunreporting', 'rancher', 'readFile', 'readJSON',
      'readManifest', 'readMavenPom', 'readProperties', 'readTrusted', 'readXml', 'readYaml', 'realtimeJUnit',
      'registerWebhook', 'release', 'resolveScm', 'retry', 'rocketSend', 'rtp', 'runConanCommand', 'runFromAlmBuilder',
      'runLoadRunnerScript', 'runValgrind', 's3CopyArtifact', 's3Delete', 's3Download', 's3FindFiles', 's3Upload',
      'salt', 'sauce', 'saucePublisher', 'sauceconnect', 'script', 'selectRun', 'sendCIMessage', 'sendDeployableMessage',
      'serviceNow_attachFile', 'serviceNow_attachZip', 'serviceNow_createChange', 'serviceNow_getCTask',
      'serviceNow_getChangeState', 'serviceNow_updateChangeItem', 'setAccountAlias', 'setGerritReview',
      'setGitHubPullRequestStatus', 'sh', 'sha1', 'signAndroidApks', 'silkcentral', 'silkcentralCollectResults',
      'slackSend', 'sleep', 'sloccountPublish', 'snsPublish', 'snykSecurity', 'sonarToGerrit', 'sparkSend',
      'splitTests', 'springBoot', 'sscm', 'sseBuild', 'sseBuildAndPublish', 'sshPublisher', 'sshagent', 'stage',
      'startET', 'startSandbox', 'startSession', 'startTS', 'stash', 'step', 'stepcounter', 'stopET', 'stopSandbox',
      'stopSession', 'stopTS', 'submitJUnitTestResultsToqTest', 'submitModuleBuildRequest', 'svChangeModeStep',
      'svDeployStep', 'svExportStep', 'svUndeployStep', 'svn', 'tagImage', 'task', 'teamconcert', 'tee', 'testFolder',
      'testPackage', 'testProject', 'testiniumExecution', 'themisRefresh', 'themisReport', 'throttle', 'time',
      'timeout', 'timestamps', 'tm', 'tool', 'touch', 'triggerInputStep', 'triggerJob', 'typetalkSend', 'uftScenarioLoad',
      'unarchive', 'unstash', 'unzip', 'updateBotPush', 'updateGitlabCommitStatus', 'updateIdP', 'updateTrustPolicy',
      'upload','pgyer', 'uploadProgetPackage', 'uploadToIncappticConnect', 'vSphere', 'validateDeclarativePipeline',
      'vmanagerLaunch', 'waitForCIMessage', 'waitForJob', 'waitForQualityGate', 'waitForWebhook', 'waitUntil',
      'walk', 'waptProReport', 'warnings', 'whitesource', 'winRMClient', 'withAWS', 'withAnt', 'withContext', 'withCoverityEnv',
      'withCredentials', 'withDockerContainer', 'withDockerRegistry', 'withDockerServer', 'withEnv', 'withKafkaLog',
      'withKubeConfig', 'withMaven', 'withNPM', 'withPod', 'withPythonEnv', 'withSCM', 'withSandbox', 'withSonarQubeEnv',
      'withTypetalk', 'wrap', 'writeFile', 'writeJSON', 'writeMavenPom', 'writeProperties', 'writeXml', 'writeYaml',
      'ws', 'xUnitImporter', 'xUnitUploader', 'xunit', 'xldCreatePackage', 'xldDeploy', 'xldPublishPackage',
      'xlrCreateRelease', 'xrayScanBuild', 'zip'
    )),

    jenkinsfile_docker_config: $ => seq(
      '{',
      repeat(choice(
        $.jenkinsfile_docker_keyword,
        $._expression
      )),
      '}'
    ),

    jenkinsfile_docker_keyword: $ => token(choice(
      'image', 'args', 'additionalBuildArgs', 'label', 'registryUrl', 'registryCredentialsId', 'alwaysPull', 'filename', 'dir'
    )),
    _expression: $ => choice(
      $.jenkinsfile_built_in_variable,
      $.jenkinsfile_section,
      $.jenkinsfile_directive,
      $.jenkinsfile_option,
      $.jenkinsfile_core_step,
      $.jenkinsfile_pipeline_step,
      $.jenkinsfile_docker_config,
      $.string,  // For capturing string literals
      $.number,  // For capturing numbers
      $.identifier,  // For capturing variable names or other identifiers
      // ... any other general Groovy expressions or constructs
      $._groovy_expression
    ),
    options_section: $ => seq(
      'options',
      '{',
      repeat($.jenkinsfile_option),
      '}'
    ),

    environment_section: $ => seq(
      'environment',
      '{',
      repeat($.environment_variable_definition),
      '}'
    ),

    environment_variable_definition: $ => seq(
      $.identifier, '=', $._expression
    ),
parameters_section: $ => seq(
  'parameters',
  '{',
  repeat($.parameter_definition),
  '}'
),

parameter_definition: $ => seq(
  $.parameter_type,
  '{',
  $.parameter_name,
  $.parameter_default_value, // Optional, you can make it optional using the optional() function if needed
  '}'
),

    parameter_type: $ => choice(
      'string',
      'booleanParam',
      'choice',
      'file',
      'password',
      'text'
      // ... add other parameter types if needed
    ),

    parameter_name: $ => seq(
      'name', '=', $.string
    ),

    parameter_default_value: $ => seq(
      'defaultValue', '=', $._expression
    ),
    triggers_section: $ => seq(
      'triggers',
      '{',
      repeat($.trigger_definition),
      '}'
    ),

    trigger_definition: $ => choice(
      $.cron_trigger,
      $.poll_scm_trigger,
      $.upstream_trigger
      // ... add other trigger types if needed
    ),

    cron_trigger: $ => seq(
      'cron', '(', $.cron_string, ')'
    ),

    poll_scm_trigger: $ => seq(
      'pollSCM', '(', $.cron_string, ')'
    ),

    upstream_trigger: $ => seq(
      'upstream',
      '(',
      'upstreamProjects:', $.job_list,
      ',',
      'threshold:', $.threshold_value,
      ')'
    ),

    cron_string: $ => choice(
      /'@yearly'/,
      /'@annually'/,
      /'@monthly'/,
      /'@weekly'/,
      /'@daily'/,
      /'@midnight'/,
      /'@hourly'/,
      seq(
        "'", 
        choice(
          /[0-5]?\d/, // Minutes (0-59)
          /\*/, // Any value
          /[0-5]?\d-[0-5]?\d/, // Range
          /[0-5]?\d-[0-5]?\d\/\d+/, // Range with step
          /\*\/\d+/ // Any value with step
        ),
        /\s+/,
        choice(
          /[01]?\d|2[0-3]/, // Hours (0-23)
          /\*/,
          /[01]?\d|2[0-3]-[01]?\d|2[0-3]/,
          /[01]?\d|2[0-3]-[01]?\d|2[0-3]\/\d+/,
          /\*\/\d+/
        ),
        /\s+/,
        choice(
          /[0-2]?\d|3[01]/, // Day of the month (1-31)
          /\*/,
          /[0-2]?\d|3[01]-[0-2]?\d|3[01]/,
          /[0-2]?\d|3[01]-[0-2]?\d|3[01]\/\d+/,
          /\*\/\d+/
        ),
        /\s+/,
        choice(
          /[0]?\d|1[0-2]/, // Month (1-12)
          /\*/,
          /[0]?\d|1[0-2]-[0]?\d|1[0-2]/,
          /[0]?\d|1[0-2]-[0]?\d|1[0-2]\/\d+/,
          /\*\/\d+/
        ),
        /\s+/,
        choice(
          /[0-7]/, // Day of the week (0-7)
          /\*/,
          /[0-7]-[0-7]/,
          /[0-7]-[0-7]\/\d+/,
          /\*\/\d+/
        ),
        "'"
      )
    ),

    tools_section: $ => seq(
      'tools',
      '{',
      repeat($.tool_definition),
      '}'
    ),

    tool_definition: $ => seq(
      $.tool_name, $._expression // This assumes the tool name followed by an expression for the version or other configuration.
    ),

    tool_name: $ => choice(
      /[\w\-]+/,           // Unquoted tool names
      /'[\w\-]+'/,        // Single-quoted tool names
      /"[\w\-]+"/         // Double-quoted tool names
    ),

    libraries_section: $ => seq(
      'libraries',
      '{',
      repeat($.library_definition),
      '}'
    ),

    library_definition: $ => seq(
      '@Library',
      '(',
      choice(
        $.library_name,           // Just the library name
        $.library_name_with_url   // Library name with URL and optional branch
      ),
      ')',
      '_'
    ),

    library_name: $ => /'[^']+'/, // Single-quoted library name

    library_name_with_url: $ => seq(
      $.library_name,
      ',',
      $.library_url,
      optional(seq(',', $.branch_name)) // Optional branch name
    ),

    library_url: $ => /'[^']+'/, // Single-quoted library URL

    branch_name: $ => /'[^']+'/, // Single-quoted branch name
    job_list: $ => /'[^']+'/, // Matches comma-separated job names enclosed in single quotes

    threshold_value: $ => choice(
      'hudson.model.Result.SUCCESS',
      // ... add other possible threshold values if needed
    ),
    when_section: $ => seq(
      'when',
      optional(choice('beforeAgent', 'beforeInput', 'beforeOptions')),
      '{',
      repeat($.when_condition),
      '}'
    ),

    when_condition: $ => choice(
      $.branch_condition,
      $.buildingTag_condition,
      $.changelog_condition,
      $.changeset_condition,
      $.changeRequest_condition,
      $.environment_condition,
      $.equals_condition,
      $.expression_condition,
      $.tag_condition,
      $.not_condition,
      $.allOf_condition,
      $.anyOf_condition,
      $.triggeredBy_condition,
      // ... add other when conditions as needed
    ),

    branch_condition: $ => seq(
      'branch',
      choice(
        $._expression, // For simple branch name
        seq('pattern:', $._expression, 'comparator:', choice('EQUALS', 'GLOB', 'REGEXP'))
      )
    ),

    buildingTag_condition: $ => 'buildingTag()',

    changelog_condition: $ => seq('changelog', $._expression),

    changeset_condition: $ => choice(
      seq(
        'changeset',
        $.string_pattern
      ),
      seq(
        'changeset',
        '{',
        optional(seq('pattern:', $.string_pattern)),
        optional(choice(
          seq('comparator:', 'EQUALS'),
          seq('comparator:', 'GLOB'),
          seq('comparator:', 'REGEXP')
        )),
        optional(seq('caseSensitive:', choice('true', 'false'))),
        '}'
      )
    ),

    string_pattern: $ => /".*?"/,
    // changeRequest_condition: $ => seq(
    //   'changeRequest',
    //   optional(seq(choice('id', 'target', 'branch', 'fork', 'url', 'title', 'author', 'authorDisplayName', 'authorEmail'), ':', $._expression, 'comparator:', choice('EQUALS', 'GLOB', 'REGEXP')))
    // ),
    changeRequest_condition: $ => choice(
      $.changeRequest_simple,
      $.changeRequest_detailed
    ),

    changeRequest_simple: $ => 'changeRequest',

    changeRequest_detailed: $ => prec(1, seq(
      'changeRequest',
      choice('id', 'target', 'branch', 'fork', 'url', 'title', 'author', 'authorDisplayName', 'authorEmail'),
      ':',
      $._expression,
      'comparator:',
      choice('EQUALS', 'GLOB', 'REGEXP')
    )),

        environment_condition: $ => seq('environment', 'name:', $._expression, 'value:', $._expression),

        equals_condition: $ => seq('equals', 'expected:', $._expression, 'actual:', $._expression),

        expression_condition: $ => seq('expression', '{', $._expression, '}'),

        tag_condition: $ => seq(
          'tag',
          choice(
            $._expression,
            seq('pattern:', $._expression, 'comparator:', choice('EQUALS', 'GLOB', 'REGEXP'))
          )
        ),

    not_condition: $ => seq('not', '{', $.when_condition, '}'),

    allOf_condition: $ => seq('allOf', '{', repeat($.when_condition), '}'),

    anyOf_condition: $ => seq('anyOf', '{', repeat($.when_condition), '}'),

    triggeredBy_condition: $ => seq('triggeredBy', choice($._expression, seq('cause:', $._expression, 'detail:', $._expression))),

    // This can be expanded to capture specific parameters or general Groovy expressions.
    _expression: $ => /[^}]+/,

    post_section: $ => seq(
      'post',
      '{',
      repeat(choice(
        $.always_block,
        $.changed_block,
        $.failure_block,
        $.success_block,
        $.unstable_block,
        $.aborted_block,
        $.regression_block,
        $.fixed_block,
        $.cleanup_block
        // ... any other post conditions
      )),
      '}'
    ),

    always_block: $ => seq('always', '{', repeat($._expression), '}'),
    changed_block: $ => seq('changed', '{', repeat($._expression), '}'),
    failure_block: $ => seq('failure', '{', repeat($._expression), '}'),
    success_block: $ => seq('success', '{', repeat($._expression), '}'),
    unsuccessful_block: $ => seq('unsuccessful', '{', repeat($._expression), '}'),
    unstable_block: $ => seq('unstable', '{', repeat($._expression), '}'),
    aborted_block: $ => seq('aborted', '{', repeat($._expression), '}'),
    regression_block: $ => seq('regression', '{', repeat($._expression), '}'),
    fixed_block: $ => seq('fixed', '{', repeat($._expression), '}'),
    cleanup_block: $ => seq('cleanup', '{', repeat($._expression), '}'),
    
    string: $ => /"[^"]*"/,
    number: $ => /\d+(\.\d+)?/,
    identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/, 
    comment: ($) => choice($.line_comment, $.block_comment),
    line_comment: ($) => token(prec(0, seq("//", /[^\n]*/))),
    block_comment: ($) =>
      token(prec(0, seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/"))),
  }
});
