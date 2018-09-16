/****** Object:  StoredProcedure [dbo].[SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet]    Script Date: 08/07/2009 14:47:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF EXISTS (SELECT * FROM sysobjects WHERE type = 'P' AND name = 'SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet')
BEGIN
DROP PROCEDURE [dbo].[SystemCenterCentral_Utilities_Certificates_TwoGroupCustomConfigurationReportDataGet]
END
GO
