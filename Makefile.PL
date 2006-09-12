use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# $Id: Makefile.PL,v 1.1 2006/09/12 10:39:59 james Exp $
WriteMakefile(
    'NAME'	=> 'Net::Pcap::Reassemble',
    'VERSION_FROM' => 'Reassemble.pm', # finds $VERSION
    'PREREQ_PM'	=> { "Net::Pcap" => "0" },
    'dist'	=> { POSTOP=>'$(CHMOD) 444 $(DISTVNAME).tar$(SUFFIX)' },
);
