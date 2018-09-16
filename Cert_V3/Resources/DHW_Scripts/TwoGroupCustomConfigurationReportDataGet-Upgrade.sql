/****** Object:  StoredProcedure [dbo].[SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet]    Script Date: 08/07/2009 14:47:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

IF NOT EXISTS (SELECT * FROM sysobjects WHERE type = 'P' AND name = 'SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet')
	BEGIN
		EXECUTE ('CREATE PROCEDURE [dbo].[SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet] AS RETURN 1')
	END
GO

ALTER PROCEDURE [dbo].[SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet]
	@StartDate datetime,
	@EndDate datetime,
	@ObjectListA xml,
	@ObjectListB xml,
	@InputXML xml,
	@LanguageCode varchar(3) = 'ENU'
AS
BEGIN

  SET NOCOUNT ON

 DECLARE @Error int
  DECLARE @ExecError int

  ---------------------------------------------------------------------
  -- Create tables
  ---------------------------------------------------------------------

  CREATE TABLE #ObjectListA
  (
	ManagedEntityRowId int
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #ObjectListB
  (
	ManagedEntityRowId int
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #ObjectListCombined
  (
	ManagedEntityRowId int
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #RelationshipList
  (
	RelationshipTypeRowId int
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #Entity_Tree
  (
	ManagedEntityRowId int,
	GroupManagedEntityRowId int,
	Level int
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #ColumnPicker
  (
	 PropertyGuid nvarchar(255)
	,Visible nvarchar(255)
	,[Position] int
	,FilterValue nvarchar(255) 
	,FilterType  nvarchar(255) 
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #PropertyList
  (
	 ManagedEntityPropertyRowId int
	,GroupManagedEntityRowId	int
	,Level						int
	,ConfigurationRecordCount	int
	,FromDateTime				datetime
	,ToDateTime					datetime
	,PropertyGuid				uniqueidentifier
	,PropertyValue				nvarchar(256)
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #ResultPropertyList
  (
	 ManagedEntityPropertyRowId int
	,GroupManagedEntityRowId	int
	,Level						int
	,ConfigurationRecordCount	int
	,FromDateTime				datetime
	,ToDateTime					datetime
	,PropertyGuid				uniqueidentifier
	,PropertyValue				nvarchar(256)
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  CREATE TABLE #IncludeObjectList
  (
	ManagedEntityRowId int
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  ---------------------------------------------------------------------
  -- Get a list of Managed Entities in Group A (direct members)
  ---------------------------------------------------------------------

  INSERT INTO #ObjectListA (ManagedEntityRowId)
  EXECUTE @ExecError = [Microsoft_SystemCenter_DataWarehouse_Report_Library_ReportObjectListParse]
    @ObjectList = @ObjectListA,
    @StartDate = @StartDate,
    @EndDate = @EndDate,
	@ContainmentLevelCount = 1,
	@ContainmentStartLevel = 1

  SET @Error = @@ERROR
  IF @Error <> 0 OR @ExecError <> 0 GOTO QuitError

  ---------------------------------------------------------------------
  -- Get a list of Managed Entities in Group B (may be up to 4 levels deep)
  ---------------------------------------------------------------------

  INSERT INTO #ObjectListB (ManagedEntityRowId)
  EXECUTE @ExecError = [Microsoft_SystemCenter_DataWarehouse_Report_Library_ReportObjectListParse]
    @ObjectList = @ObjectListB,
    @StartDate = @StartDate,
    @EndDate = @EndDate,
	@ContainmentLevelCount = 4,
	@ContainmentStartLevel = 1

  SET @Error = @@ERROR
  IF @Error <> 0 OR @ExecError <> 0 GOTO QuitError

 ---------------------------------------------------------------------
  -- Get a list of Managed Entities which are members of both groups
  ---------------------------------------------------------------------
 INSERT INTO #ObjectListCombined (ManagedEntityRowId)
 SELECT ManagedEntityRowId 
 FROM #ObjectListA
 WHERE  ManagedEntityRowId IN 
	(
		SELECT ManagedEntityRowId 
		FROM #ObjectListB
	)
  

  ---------------------------------------------------------------------
  -- Get list of all relationships derived from 'System.Hosting'
  ---------------------------------------------------------------------
  INSERT #RelationshipList 
  SELECT RelationshipTypeRowId 
  from RelationshipDerivedTypeHierarchy 
  (
	(
		SELECT RelationshipTypeRowId 
		FROM dbo.vRelationshipType 
		WHERE RelationshipTypeSystemName = 'System.Hosting'
	)
	,0
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

 

 ---------------------------------------------------------------------
  -- Get list of all entities above the selected objects in their respective hosting chains
  ---------------------------------------------------------------------

  INSERT #Entity_Tree
  SELECT ManagedEntityRowId  AS ManagedEntityRowId
		,ManagedEntityRowId  AS GroupManagedEntityRowId
		,0 AS Level
  FROM #ObjectListCombined

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  declare @count int
  declare @level int
  set @count = 1
  set @level = 0

  while @count > 0
  begin
		INSERT #Entity_Tree
		SELECT r.SourceManagedEntityRowId,
			   et.GroupManagedEntityRowId,
			   et.Level + 1
		FROM vRelationship AS r
			JOIN #Entity_Tree AS et ON r.TargetManagedEntityRowId = et.ManagedEntityRowId
			JOIN #RelationshipList rl ON r.RelationshipTypeRowId = rl.RelationshipTypeRowId
		WHERE et.Level = @level

        SELECT @Error = @@ERROR, @count = @@ROWCOUNT
		set @level = @level + 1

	    IF @Error <> 0 GOTO QuitError
  end

  ---------------------------------------------------------------------
  -- Open XML from ColumnPickerControl For Parsing
  ---------------------------------------------------------------------
  DECLARE @xmldoc int
  EXEC @ExecError = sp_xml_preparedocument @xmldoc OUTPUT, @InputXML

  SET @Error = @@ERROR
  IF @ExecError <> 0 OR @Error <> 0 GOTO QuitError

  ---------------------------------------------------------------------
  -- Parse Column Picker XML
  ---------------------------------------------------------------------

  INSERT INTO #ColumnPicker
  SELECT PropertyGuid,Visible, [Position],FilterValue,FilterType
  FROM OPENXML(@xmldoc, '/Data/Columns/Column', 2) WITH
  (
	PropertyGuid uniqueidentifier 'ID',
	Visible nvarchar(255) '@Visible',
	[Position] int '@mp:id',
	FilterValue nvarchar(255) 'Filter',
	FilterType  nvarchar(255) './Filter/@Type'
  )

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  ---------------------------------------------------------------------
  -- Get List of Selected Properties and values for selected Objects
  ---------------------------------------------------------------------

  INSERT INTO #PropertyList
  SELECT DISTINCT
		  vManagedEntityProperty.ManagedEntityPropertyRowId
		 ,P.GroupManagedEntityRowId
		 ,P.Level
		 ,P.ConfigurationRecordCount
		 ,vManagedEntityProperty.FromDateTime
		 ,vManagedEntityProperty.ToDateTime
		 ,T.PropertyXML.value('@Guid','uniqueidentifier') AS PropertyGuid
		 ,T.PropertyXML.value('.','nvarchar(256)') AS PropertyValue

  FROM	vManagedEntityProperty INNER JOIN
		(
		  /* Select last property from the list */
		  SELECT  MAX(vManagedEntityProperty.ManagedEntityPropertyRowId) AS ManagedEntityPropertyRowId
				 ,#Entity_Tree.GroupManagedEntityRowId
				 ,#Entity_Tree.Level
				 ,COUNT(DISTINCT vManagedEntityProperty.ManagedEntityPropertyRowId) AS ConfigurationRecordCount
		  FROM	vManagedEntityProperty
				INNER JOIN #Entity_Tree ON vManagedEntityProperty.ManagedEntityRowId = #Entity_Tree.ManagedEntityRowId
		  WHERE (vManagedEntityProperty.FromDateTime < @EndDate) AND (@StartDate <= ISNULL(vManagedEntityProperty.ToDateTime, '99991231'))
		  GROUP BY vManagedEntityProperty.ManagedEntityRowId, #Entity_Tree.GroupManagedEntityRowId, #Entity_Tree.Level

		) AS P ON P.ManagedEntityPropertyRowId = vManagedEntityProperty.ManagedEntityPropertyRowId

      CROSS APPLY PropertyXml.nodes('/Root/Property') AS T(PropertyXML)
	  INNER JOIN #ColumnPicker ON #ColumnPicker.PropertyGuid = T.PropertyXML.value('@Guid','uniqueidentifier')

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  -- Get result list of properties

  INSERT INTO #ResultPropertyList
  SELECT  #PropertyList.ManagedEntityPropertyRowId
		 ,#PropertyList.GroupManagedEntityRowId
		 ,#PropertyList.Level
		 ,#PropertyList.ConfigurationRecordCount
		 ,#PropertyList.FromDateTime
		 ,#PropertyList.ToDateTime
		 ,#PropertyList.PropertyGuid
		 ,#PropertyList.PropertyValue

  FROM #PropertyList INNER JOIN
  (
	  	SELECT	 GroupManagedEntityRowId
				,MIN(Level) as Level
				,PropertyGuid
		FROM	#PropertyList
		GROUP BY GroupManagedEntityRowId ,PropertyGuid

  ) As PropertyMinList ON #PropertyList.PropertyGuid = PropertyMinList.PropertyGuid AND
						  #PropertyList.Level = PropertyMinList.Level AND
						  #PropertyList.GroupManagedEntityRowId = PropertyMinList.GroupManagedEntityRowId

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  -- Build object filter

  IF (EXISTS (SELECT * FROM #ColumnPicker WHERE NOT (#ColumnPicker.FilterType IS NULL)))
    BEGIN
		INSERT #IncludeObjectList
		SELECT DISTINCT GroupManagedEntityRowId
		FROM  #ResultPropertyList
			  INNER JOIN #ColumnPicker ON #ColumnPicker.PropertyGuid = #ResultPropertyList.PropertyGuid
		WHERE ((#ColumnPicker.FilterType = 'Equals') AND (#ResultPropertyList.PropertyValue = #ColumnPicker.FilterValue)) OR
			  ((#ColumnPicker.FilterType = 'Contains')AND (#ResultPropertyList.PropertyValue LIKE ('%' + #ColumnPicker.FilterValue + '%')))
    END
  ELSE
    BEGIN
		INSERT #IncludeObjectList
		SELECT DISTINCT GroupManagedEntityRowId
		FROM #ResultPropertyList
    END

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

  ---------------------------------------------------------------------
  -- Select Filtered list of properties for selected objects
  ---------------------------------------------------------------------
  SELECT  #ResultPropertyList.ManagedEntityPropertyRowId
		 ,#ResultPropertyList.GroupManagedEntityRowId AS ManagedEntityRowId
		 ,#ResultPropertyList.Level
		 ,#ResultPropertyList.ConfigurationRecordCount
		 ,#ResultPropertyList.FromDateTime
		 ,#ResultPropertyList.ToDateTime
		 ,#ResultPropertyList.PropertyGuid
		 ,#ResultPropertyList.PropertyValue
		 ,#ColumnPicker.Position
		 ,PropertyType.ManagedEntityTypeGuid AS PropertyTypeGuid
		 ,ISNULL(displayPropertyType.Name,PropertyType.ManagedEntityTypeDefaultName) AS PropertyTypeDefaultName
		 ,vManagedEntity.ManagedEntityDefaultName AS RelatedManagedEntityDefaultName
		 ,vManagedEntity.ManagedEntityRowId AS RelatedManagedEntityRowId
		 ,GroupEntity.ManagedEntityGuid
		 ,GroupEntity.ManagedEntityDefaultName
		 ,GroupEntity.Path
		 ,vManagementGroup.ManagementGroupDefaultName
		 ,vManagementGroup.ManagementGroupGuid
		 ,vManagedEntityType.ManagedEntityTypeGuid
		 ,ISNULL(vDisplayString.Name,vManagedEntityType.ManagedEntityTypeDefaultName)AS DisplayName
		 ,vManagedEntityTypeImage.Image
		 ,ISNULL(displayProperty.Name,vManagedEntityTypeProperty.PropertyDefaultName) as PropertyDefaultName  
  FROM	#ResultPropertyList
		INNER JOIN #IncludeObjectList ON #IncludeObjectList.ManagedEntityRowId = #ResultPropertyList.GroupManagedEntityRowId
		INNER JOIN #ColumnPicker ON #ColumnPicker.PropertyGuid = #ResultPropertyList.PropertyGuid
		INNER JOIN vManagedEntityTypeProperty ON vManagedEntityTypeProperty.PropertyGuid = #ResultPropertyList.PropertyGuid 
		INNER JOIN vManagedEntityProperty ON vManagedEntityProperty.ManagedEntityPropertyRowId = #ResultPropertyList.ManagedEntityPropertyRowId
		INNER JOIN vManagedEntityType AS PropertyType ON PropertyType.ManagedEntityTypeRowId = vManagedEntityTypeProperty.ManagedEntityTypeRowId

		INNER JOIN vManagedEntity ON vManagedEntityProperty.ManagedEntityRowId = vManagedEntity.ManagedEntityRowId 
		INNER JOIN vManagedEntity AS GroupEntity ON #ResultPropertyList.GroupManagedEntityRowId = GroupEntity.ManagedEntityRowId 
		INNER JOIN vManagedEntityType ON vManagedEntityType.ManagedEntityTypeRowId = GroupEntity.ManagedEntityTypeRowId
		INNER JOIN vManagementGroup ON GroupEntity.ManagementGroupRowId = vManagementGroup.ManagementGroupRowId
		INNER JOIN vManagedEntityTypeImage ON GroupEntity.ManagedEntityTypeRowId = vManagedEntityTypeImage.ManagedEntityTypeRowId 
        AND vManagedEntityTypeImage.ImageCategory = N'u16x16Icon' 
        LEFT OUTER JOIN vDisplayString ON vManagedEntityType.ManagedEntityTypeGuid = vDisplayString.ElementGuid 
        AND vDisplayString.LanguageCode = @LanguageCode
		LEFT OUTER JOIN vDisplayString displayProperty ON vManagedEntityTypeProperty.PropertyGuid = displayProperty.ElementGuid
        AND displayProperty.LanguageCode = @LanguageCode
        LEFT OUTER JOIN vDisplayString displayPropertyType ON vManagedEntityType.ManagedEntityTypeGuid = displayPropertyType.ElementGuid
        AND displayPropertyType.LanguageCode = @LanguageCode
		

  WHERE #ColumnPicker.Visible = 'True'
  ORDER BY Position

  SET @Error = @@ERROR
  IF @Error <> 0 GOTO QuitError

---------------------------------------------------------------------
--Error Handling & Cleanup code
---------------------------------------------------------------------

QuitError:
  IF ((@Error = 0) AND (@ExecError <> 0)) SET @Error = @ExecError

  -- remove xml document if opened
  IF @xmldoc IS NOT NULL EXEC sp_xml_removedocument @xmldoc

  DROP TABLE #IncludeObjectList
  DROP TABLE #ResultPropertyList
  DROP TABLE #PropertyList
  DROP TABLE #ColumnPicker
  DROP TABLE #Entity_Tree
  DROP TABLE #RelationshipList
  DROP TABLE #ObjectListA
  DROP TABLE #ObjectListB
  DROP TABLE #ObjectListCombined

  RETURN @Error

END

GO
GRANT EXECUTE ON [dbo].[SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet] TO OpsMgrReader
GO