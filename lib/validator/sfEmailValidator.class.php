<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 * (c) 2004-2006 Sean Kerr <sean@code-box.org>
 * 
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * sfEmailValidator verifies a parameter contains a value that qualifies as an
 * email address.
 *
 * @package    symfony
 * @subpackage validator
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @author     Sean Kerr <sean@code-box.org>
 * @version    SVN: $Id: sfEmailValidator.class.php 8838 2008-05-07 16:53:50Z nicolas $
 */
class sfEmailValidator extends sfValidator
{
  /**
   * Executes this validator.
   *
   * @param mixed A file or parameter value/array
   * @param error An error message reference
   *
   * @return bool true, if this validator executes successfully, otherwise false
   */
  public function execute(&$value, &$error)
  {
    $strict = $this->getParameterHolder()->get('strict');
    if ($strict == true)
    {
      $re = '/^([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})$/i';
      //Obtenido de http://emailregex.com/
      $re='/^(?!(?:(?:\x22?\x5C[\x00-\x7E]\x22?)|(?:\x22?[^\x5C\x22]\x22?)){255,})(?!(?:(?:\x22?\x5C[\x00-\x7E]\x22?)|(?:\x22?[^\x5C\x22]\x22?)){65,}@)(?:(?:[\x21\x23-\x27\x2A\x2B\x2D\x2F-\x39\x3D\x3F\x5E-\x7E]+)|(?:\x22(?:[\x01-\x08\x0B\x0C\x0E-\x1F\x21\x23-\x5B\x5D-\x7F]|(?:\x5C[\x00-\x7F]))*\x22))(?:\.(?:(?:[\x21\x23-\x27\x2A\x2B\x2D\x2F-\x39\x3D\x3F\x5E-\x7E]+)|(?:\x22(?:[\x01-\x08\x0B\x0C\x0E-\x1F\x21\x23-\x5B\x5D-\x7F]|(?:\x5C[\x00-\x7F]))*\x22)))*@(?:(?:(?!.*[^.]{64,})(?:(?:(?:xn--)?[a-z0-9]+(?:-[a-z0-9]+)*\.){1,126}){1,}(?:(?:[a-z][a-z0-9]*)|(?:(?:xn--)[a-z0-9]+))(?:-[a-z0-9]+)*)|(?:\[(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){7})|(?:(?!(?:.*[a-f0-9][:\]]){7,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?)))|(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){5}:)|(?:(?!(?:.*[a-f0-9]:){5,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3}:)?)))?(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))(?:\.(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))){3}))\]))$/iD';
    }
    else
    {
      /* Cal Henderson: http://iamcal.com/publish/articles/php/parsing_email/pdf/
       * The long regular expression below is made by the following code
       * fragment:
       *
       *   $qtext = '[^\\x0d\\x22\\x5c\\x80-\\xff]';
       *   $dtext = '[^\\x0d\\x5b-\\x5d\\x80-\\xff]';
       *   $atom = '[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c'
       *         . '\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+';
       *   $quoted_pair = '\\x5c\\x00-\\x7f';
       *   $domain_literal = "\\x5b($dtext|$quoted_pair)*\\x5d";
       *   $quoted_string = "\\x22($qtext|$quoted_pair)*\\x22";
       *   $domain_ref = $atom;
       *   $sub_domain = "($domain_ref|$domain_literal)";
       *   $word = "($atom|$quoted_string)";
       *   $domain = "$sub_domain(\\x2e$sub_domain)*";
       *   $local_part = "$word(\\x2e$word)*";
       *   $addr_spec = "$local_part\\x40$domain";
       */

      $re = '/^([^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-'
           .'\\x5d\\x7f-\\xff]+|\\x22([^\\x0d\\x22\\x5c\\x80-\\xff]|\\x5c\\x00-'
           .'\\x7f)*\\x22)(\\x2e([^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-'
           .'\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+|\\x22([^\\x0d\\x22\\x5c\\x80'
           .'-\\xff]|\\x5c\\x00-\\x7f)*\\x22))*\\x40([^\\x00-\\x20\\x22\\x28\\x29'
           .'\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+|\\x5b([^'
           .'\\x0d\\x5b-\\x5d\\x80-\\xff]|\\x5c\\x00-\\x7f)*\\x5d)(\\x2e([^\\x00-'
           .'\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-'
           .'\\xff]+|\\x5b([^\\x0d\\x5b-\\x5d\\x80-\\xff]|\\x5c\\x00-\\x7f)*'
           .'\\x5d))*$/'
      ;
    }

    if (!preg_match($re, $value))
    {
      $error = $this->getParameterHolder()->get('email_error');
      return false;
    }

    $checkDomain = $this->getParameterHolder()->get('check_domain');
    if ($checkDomain && function_exists('checkdnsrr'))
    {
      $tokens = explode('@', $value);
      if (!checkdnsrr($tokens[1], 'MX') && !checkdnsrr($tokens[1], 'A'))
      {
        $error = $this->getParameterHolder()->get('email_error');

        return false;
      }
    }

    return true;
  }

  /**
   * Initializes this validator.
   *
   * @param sfContext The current application context
   * @param array   An associative array of initialization parameters
   *
   * @return bool true, if initialization completes successfully, otherwise false
   */
  public function initialize($context, $parameters = null)
  {
    // initialize parent
    parent::initialize($context);

    // set defaults
    $this->getParameterHolder()->set('strict',       true);
    $this->getParameterHolder()->set('check_domain', false);
    $this->getParameterHolder()->set('email_error',  'Invalid input');

    $this->getParameterHolder()->add($parameters);

    return true;
  }
}
