package com.crowdstrike.plugins.crwds.configuration;

public interface FalconConfiguration {

    boolean getEnforce();

    String getImageName();

    String getImageTag();

    Integer getTimeout();

    String getFalconCredentialId();

    String getFalconCloud();
}
