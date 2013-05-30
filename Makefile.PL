use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Regexp::Convert::XMLSchema',
    VERSION_FROM      => 'lib/Regexp/Convert/XMLSchema.pm', # finds $VERSION
    PREREQ_PM         => { YAPE::Regex => 3.0 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Regexp/Convert/XMLSchema.pm', # retrieve abstract from module
       AUTHOR         => 'Bjoern Hoehrmann <bjoern@hoehrmann.de>') : ()),
);
