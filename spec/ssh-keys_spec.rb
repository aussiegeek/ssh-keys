require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "SshKeys" do
  context "check key validity" do
    it "should fail when its just not a key" do
      lambda {Aussiegeek::SshKey.new('not a key')}.should raise_error(Aussiegeek::SshKey::InvalidKey)
    end
  end

  it "shouldn't allow a key with a newline in it" do
    key="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAu9l5Vlc0g8QefXEhOZ8F0ma3
    Ea0STP0gGkq8MPsjNhtksB58YxyOfdQFF1jdSAb1F8OfzQOsnTxepN0LEBKhEbUPxD2FBcHUvKUcl0q75rSwdlbkd+lx4FRARIf3siQwVatfHI6XWYSX3nM/hu2/LXq8oxRxYLdmHaq2khzBW9ZpF0i1FcaC77rxSXbW6FjGyebtGnsKEn8uTFxXhlEQBFb+DKw31KzAOfPNXzMLuXA5kyMGqIGq5vdp82js71enyvsHIYzuYddS84tRVXDgKR8nOXtCpzB9SmV+bjKj3H67cl3D5lEjWLpw+IpwCjqSCC26yBHJgXBXUPBnbnt+EQ== alan@Nibbler.local"
    lambda {Aussiegeek::SshKey.new(key)}.should raise_error(Aussiegeek::SshKey::InvalidKey)
  end

  it "shouldn't allow a key less than 64 characters" do
    lambda {Aussiegeek::SshKey.new('short')}.should raise_error(Aussiegeek::SshKey::InvalidKey)
  end
  
  context "get key info (rsa)" do
    before do
      @ssh_key = Aussiegeek::SshKey.new('ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAu9l5Vlc0g8QefXEhOZ8F0ma3Ea0STP0gGkq8MPsjNhtksB58YxyOfdQFF1jdSAb1F8OfzQOsnTxepN0LEBKhEbUPxD2FBcHUvKUcl0q75rSwdlbkd+lx4FRARIf3siQwVatfHI6XWYSX3nM/hu2/LXq8oxRxYLdmHaq2khzBW9ZpF0i1FcaC77rxSXbW6FjGyebtGnsKEn8uTFxXhlEQBFb+DKw31KzAOfPNXzMLuXA5kyMGqIGq5vdp82js71enyvsHIYzuYddS84tRVXDgKR8nOXtCpzB9SmV+bjKj3H67cl3D5lEjWLpw+IpwCjqSCC26yBHJgXBXUPBnbnt+EQ== alan@Nibbler.local')
    end
    
    it "should return key type" do
      @ssh_key.key_type.should == 'rsa'
    end

    it "should return key length" do
      @ssh_key.key_length.should == 2048
    end

    it "should return key fingerprint" do
      @ssh_key.fingerprint.should == '6a:2f:6c:4e:ba:3f:3f:2c:e5:5b:29:5a:e3:69:be:93'
    end
  end
  
  context "get key info (rsa1)" do
    before do
      @ssh_key = Aussiegeek::SshKey.new('2048 35 28949829256666495327055203808783564703290559194908718746265980847605543577063188549312458206643537409762851897701354095163160190205466598052061208489685449682279573413558344269285882370698563577428032229724455885452739156766425911993017437918774525170718984198334443333014655220064685623480808624143666105447032634001976981200163463137398812221145813893410549390569709006669712458058567512601416859202411346657224522766330533328884824873381922224709799360523719086235718822197002436590478198672485152026564300632186154063468070725722437239114558123196813477774459564825237317125941572363142944588989514980408611614099 alan@Nibbler.local')
    end
    
    it "should return key type" do
      @ssh_key.key_type.should == 'rsa1'
    end

    it "should return key length" do
      @ssh_key.key_length.should == 2048
    end

    it "should return key fingerprint" do
      @ssh_key.fingerprint.should == 'e1:3c:4b:90:08:3e:c3:e5:77:4f:77:c9:c2:0f:b1:90'
    end
  end
  
  context "get key info (dsa)" do
    before do
      @ssh_key = Aussiegeek::SshKey.new('ssh-dss AAAAB3NzaC1kc3MAAACBANYxHheyA7WqhelvcQNSWZ2ATcK0hjffhpZ7w2YRSzNPlizbrbuWIKhoJe6tkzHJ8RkubOX0LRfW1Iyx55kwq5I9vHkHDJRTqEUvp6Zz2A30vevVHgjNrwGv3FTf0mFeeGqN7SQzbDoPmXcwZJDLSasgYTMGR4bKd/LaOvxbdAMhAAAAFQDyn0EnpLebOMxIDCm6Wq52nCqkCwAAAIEAoSePK4RUw1f2ubsmDZ8MCYcZ+pj/boQOtRxVvgIVEsMq2JR7jHhrtlKx5DLYcKlQ+VbwnPzVOgc0XVrLtnW82lfXQ4Qy9Tp1qgALBI6zqfe38qoHX62cn8ZV7/5nPTSpjM8iN7cbiYz0KEvO5V4AgrCbZuoBQ6x0iVryjl4OfZcAAACAdnOkhHAcLw6iDuiorrU4pE83TC4cFIUS7+31vXIqMi87dXP2nAIRjkPfTTn9+gwP6KG5N7Bf1N6byvGpRB7wnVcN1Bl//45vR00ekwfzyM5LzCph+mrvq6XTL6L80quZUf1+QLsHFTN90CI1f8b0QjqOmulnnnw1t23yKw9rAa0= alan@Nibbler.local')
    end
    
    it "should return key type" do
      @ssh_key.key_type.should == 'dsa'
    end

    it "should return key length" do
      @ssh_key.key_length.should == 1024
    end

    it "should return key fingerprint" do
      @ssh_key.fingerprint.should == 'ab:7c:75:e6:85:f2:3b:4f:1f:c8:90:86:01:73:47:05'
    end
  end
end
